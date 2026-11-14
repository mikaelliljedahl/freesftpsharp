#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace SshServerModule.Authentication;

/// <summary>
/// The authentication providers of the operator (issue #64), section <c>Auth</c>. Nothing is required: without a
/// setting only the database provider checks the logins, as before.
/// </summary>
public sealed class AuthenticationOptions
{
    public const string SectionName = "Auth";

    /// <summary>
    /// The order of the providers (<c>Auth:Providers</c>, a list of names such as <c>["database", "ldap"]</c>). Empty: the
    /// database first, then the other registered providers in the order of their registration. A registered provider
    /// that is not in a non-empty list is not used.
    /// </summary>
    public List<string> Providers { get; set; } = new();

    /// <summary>
    /// <c>Auth:ExternalUsers:RootDirectory</c>: a user that an external provider creates gets
    /// <c>&lt;RootDirectory&gt;/&lt;username&gt;</c> as its root directory (the local disk, for a user whose groups give
    /// no storage). Empty: no root directory; then give the storage through a group (a storage template with
    /// <c>%username%</c>), otherwise the SFTP subsystem of such a user is refused.
    /// </summary>
    public string? ExternalUsersRootDirectory { get; set; }

    public static void Bind(AuthenticationOptions options, IConfiguration configuration)
    {
        options.Providers = configuration.GetSection($"{SectionName}:{nameof(Providers)}").GetChildren()
            .Select(c => c.Value?.Trim())
            .Where(v => !string.IsNullOrEmpty(v))
            .Select(v => v!)
            .ToList();
        var root = configuration[$"{SectionName}:ExternalUsers:RootDirectory"];
        options.ExternalUsersRootDirectory = string.IsNullOrWhiteSpace(root) ? null : root.Trim();
    }
}

/// <summary>Checks the order list: no name twice. Unknown names are checked by <see cref="UserAuthenticator"/>, which knows the registered providers.</summary>
public sealed class AuthenticationOptionsValidator : IValidateOptions<AuthenticationOptions>
{
    public ValidateOptionsResult Validate(string? name, AuthenticationOptions options)
    {
        var errors = new List<string>();
        var duplicates = options.Providers.GroupBy(p => p, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        if (duplicates.Count > 0)
            errors.Add($"{AuthenticationOptions.SectionName}:Providers names a provider more than once: {string.Join(", ", duplicates)}.");
        if (options.ExternalUsersRootDirectory is { } root && !Path.IsPathFullyQualified(root))
            errors.Add($"{AuthenticationOptions.SectionName}:ExternalUsers:RootDirectory must be an absolute path.");
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
