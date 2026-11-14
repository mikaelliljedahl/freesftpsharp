#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Net;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Users;

namespace SshServerModule.Authentication;

/// <summary>
/// Creates and updates the users of the external providers "just in time" (issue #64): <see cref="Prepare"/> makes the
/// user from the <see cref="ExternalUser"/> of a provider in memory, the protocol checks it like a stored user, and
/// <see cref="Save"/> stores it when the login is verified. The group names become the group ids (#61), so the storage
/// and the permissions come from the template groups. The status, the expiry and the credential are never set here.
/// </summary>
public sealed class ExternalUserProvisioner
{
    private readonly ISettingsRepository _repository;
    private readonly string? _rootDirectory;
    private readonly ILogger _logger;

    public ExternalUserProvisioner(ISettingsRepository repository, string? externalUsersRootDirectory, ILogger? logger = null)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _rootDirectory = externalUsersRootDirectory;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
    }

    /// <summary>
    /// The user to log in after <paramref name="provider"/> accepted the credential: the stored one, or a copy (not
    /// saved) with the definition applied. Returns the reason in <c>Error</c> when the definition cannot be used.
    /// </summary>
    public (User? User, bool NeedsSave, string? Error) Prepare(string provider, string username, ExternalUser? definition, User? stored)
    {
        if (stored != null && definition == null)
            return (stored, false, null);

        if (stored == null && ValidateNewName(username) is { } nameError)
            return (null, false, nameError);

        var candidate = stored?.ShallowCopy() ?? NewUser(provider, username);
        if (definition != null && Apply(definition, candidate) is { } definitionError)
            return (null, false, definitionError);

        return (candidate, stored == null || ManagedFieldsDiffer(stored, candidate), null);
    }

    /// <summary>
    /// Saves a prepared user. The fields of the provider are copied onto the stored user as it is now, so a change of the
    /// administrator in the meantime is kept. False when it cannot be saved, or when the name belongs to a user of
    /// another provider now.
    /// </summary>
    public bool Save(User prepared)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        var stored = _repository.GetUser(prepared.Username);
        if (stored == null)
        {
            CreateRootDirectory(prepared);
            if (_repository.AddUser(prepared))
            {
                _logger.LogInformation("Created user {Username} from the authentication provider {Provider}.", LogText.Clean(prepared.Username), prepared.AuthenticationProvider);
                return true;
            }
            stored = _repository.GetUser(prepared.Username); // another login created it at the same time
            if (stored == null)
                return false;
        }

        if (!string.Equals(stored.AuthenticationProvider, prepared.AuthenticationProvider, StringComparison.Ordinal))
        {
            _logger.LogWarning("User {Username} belongs to the authentication provider {Owner}, not to {Provider}; it is not changed.",
                LogText.Clean(prepared.Username), stored.AuthenticationProvider ?? DatabaseAuthenticationProvider.ProviderName, prepared.AuthenticationProvider);
            return false;
        }

        if (!ManagedFieldsDiffer(stored, prepared))
            return true;
        var updated = stored.ShallowCopy();
        CopyManagedFields(prepared, updated);
        if (!_repository.UpdateUser(updated))
            return false;
        _logger.LogInformation("Updated user {Username} from the authentication provider {Provider}.", LogText.Clean(prepared.Username), prepared.AuthenticationProvider);
        return true;
    }

    /// <summary>The root directory of a new user, like the command line does. A failure is logged; the storage refuses the session then.</summary>
    private void CreateRootDirectory(User user)
    {
        if (string.IsNullOrEmpty(user.UserRootDirectory))
            return;
        try
        {
            Directory.CreateDirectory(user.UserRootDirectory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            _logger.LogWarning(ex, "The root directory of user {Username} cannot be created.", LogText.Clean(user.Username));
        }
    }

    private User NewUser(string provider, string username) => new()
    {
        Username = username,
        AuthenticationProvider = provider,
        UserRootDirectory = _rootDirectory == null ? string.Empty : Path.Combine(_rootDirectory, username),
        HashedPassword = null,
        PublicKeys = null,
        OnlyWhitelistedIps = false,
        WhitelistedIps = new List<string>(),
    };

    private static string? ValidateNewName(string username)
    {
        if (UserAdministrationService.ValidateUserName(username) is { } error)
            return "the user cannot be created: " + error;
        if (username is "." or "..")
            return "the user cannot be created: the name is not valid";
        return null;
    }

    /// <summary>Applies the definition to <paramref name="user"/> (a copy); the reason when a value is not valid.</summary>
    private string? Apply(ExternalUser definition, User user)
    {
        if (definition.PrimaryGroup != null || definition.Groups != null)
        {
            var groups = _repository.GetGroups();
            int? Find(string name)
            {
                var group = groups.FirstOrDefault(g => string.Equals(g.Name, name.Trim(), StringComparison.OrdinalIgnoreCase));
                if (group == null)
                    _logger.LogWarning("The authentication provider of user {Username} gave the group {Group}, which does not exist; it is skipped.",
                        LogText.Clean(user.Username), LogText.Clean(name));
                return group?.Id;
            }

            if (definition.PrimaryGroup != null)
                user.PrimaryGroupId = string.IsNullOrWhiteSpace(definition.PrimaryGroup) ? null : Find(definition.PrimaryGroup);
            if (definition.Groups != null)
                user.SecondaryGroupIds = definition.Groups
                    .Where(n => !string.IsNullOrWhiteSpace(n))
                    .Select(Find)
                    .OfType<int>()
                    .Where(id => id != user.PrimaryGroupId)
                    .Distinct()
                    .ToList();
            else if (user.PrimaryGroupId is { } primary)
                user.SecondaryGroupIds = (user.SecondaryGroupIds ?? []).Where(id => id != primary).ToList();
        }

        if (definition.Permissions != null)
        {
            var permissions = definition.Permissions.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
            var problems = PermissionRulesValidator.Validate(permissions, null);
            if (problems.Count > 0)
                return "the permissions of the provider are not valid: " + string.Join(" ", problems);
            user.Permissions = permissions.Count == 0 ? null : permissions;
        }

        if (definition.AllowedIps != null)
        {
            var invalid = CidrNotation.FindInvalid(definition.AllowedIps);
            if (invalid.Count > 0)
                return "the networks of the provider are not valid: " + string.Join(", ", invalid);
            user.WhitelistedIps = definition.AllowedIps.Select(ip => ip.Trim()).ToList();
            user.OnlyWhitelistedIps = definition.OnlyAllowedIps ?? user.WhitelistedIps.Count > 0;
        }
        else if (definition.OnlyAllowedIps is { } onlyAllowed)
        {
            user.OnlyWhitelistedIps = onlyAllowed;
        }

        if (definition.MaxSessions is { } maxSessions)
        {
            if (maxSessions < 0)
                return "the session limit of the provider is not valid";
            user.MaxSessions = maxSessions;
        }

        if (definition.AllowedProtocols is { } protocols)
        {
            if ((protocols & UserProtocols.All) == UserProtocols.None)
                return "the protocols of the provider are not valid: allow at least one protocol";
            user.AllowedProtocols = protocols;
        }

        if (definition.Description != null)
            user.Description = definition.Description.Length > 1000 ? definition.Description[..1000] : definition.Description;
        return null;
    }

    private static void CopyManagedFields(User from, User to)
    {
        to.PrimaryGroupId = from.PrimaryGroupId;
        to.SecondaryGroupIds = (from.SecondaryGroupIds ?? []).ToList();
        to.Permissions = from.Permissions?.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
        to.OnlyWhitelistedIps = from.OnlyWhitelistedIps;
        to.WhitelistedIps = from.WhitelistedIps?.ToList();
        to.MaxSessions = from.MaxSessions;
        to.Description = from.Description;
        to.AllowedProtocols = from.AllowedProtocols;
    }

    private static bool ManagedFieldsDiffer(User a, User b) =>
        a.PrimaryGroupId != b.PrimaryGroupId
        || !(a.SecondaryGroupIds ?? []).SequenceEqual(b.SecondaryGroupIds ?? [])
        || !SamePermissions(a.Permissions, b.Permissions)
        || a.OnlyWhitelistedIps != b.OnlyWhitelistedIps
        || !(a.WhitelistedIps ?? []).SequenceEqual(b.WhitelistedIps ?? [])
        || a.MaxSessions != b.MaxSessions
        || !string.Equals(a.Description, b.Description, StringComparison.Ordinal)
        || a.AllowedProtocols != b.AllowedProtocols;

    private static bool SamePermissions(Dictionary<string, FilePermissions>? a, Dictionary<string, FilePermissions>? b)
    {
        if (a is not { Count: > 0 })
            return b is not { Count: > 0 };
        if (b is not { Count: > 0 } || a.Count != b.Count)
            return false;
        return a.All(p => b.TryGetValue(p.Key, out var value) && value == p.Value);
    }
}
