#nullable enable
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.SshServerModule;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;

namespace SshServerModule.Authentication;

/// <summary>
/// The chain of the authentication providers (issue #64), see <see cref="IUserAuthenticator"/>. The providers run in
/// the order of <see cref="AuthenticationOptions.Providers"/>; the first success or failure wins. A stored user is only
/// checked by the provider that owns it (<see cref="User.AuthenticationProvider"/>, null: the database), so a directory
/// cannot take over a local user with the same name, and a local password never opens an account of a directory.
/// </summary>
public sealed class UserAuthenticator : IUserAuthenticator
{
    private readonly IReadOnlyList<IAuthenticationProvider> _providers;
    private readonly ExternalUserProvisioner _provisioner;
    private readonly ILogger _logger;

    /// <summary>The mean time of a refused password per external provider, for <see cref="SpendFailureTimeAsync"/>.</summary>
    private readonly ConcurrentDictionary<string, FailureTime> _failureTimes = new(StringComparer.Ordinal);

    /// <param name="provisioner">The just-in-time users (shared with the OpenID Connect sign-in of the web client, #73). Null: one over <paramref name="repository"/>.</param>
    /// <exception cref="InvalidOperationException"><c>Auth:Providers</c> names a provider that is not registered.</exception>
    public UserAuthenticator(IEnumerable<IAuthenticationProvider> providers, ISettingsRepository repository,
        IOptions<AuthenticationOptions>? options = null, ILogger<UserAuthenticator>? logger = null, ExternalUserProvisioner? provisioner = null)
    {
        ArgumentNullException.ThrowIfNull(providers);
        _logger = (ILogger?)logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
        var settings = options?.Value ?? new AuthenticationOptions();
        _providers = Order(providers.ToList(), settings.Providers, _logger);
        _provisioner = provisioner ?? new ExternalUserProvisioner(repository, settings.ExternalUsersRootDirectory, _logger);
        if (HasExternalProviders)
            _logger.LogInformation("Authentication providers in order: {Providers}.", string.Join(", ", ProviderNames));
    }

    /// <summary>The names of the providers in the order in which they are asked.</summary>
    public IReadOnlyList<string> ProviderNames => _providers.Select(p => p.Name).ToList();

    public bool HasExternalProviders => _providers.Any(p => !IsDatabase(p.Name));

    public async ValueTask<CredentialCheck> VerifyAsync(AuthRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var stored = request.StoredUser;
        var owner = stored == null ? null : stored.AuthenticationProvider ?? DatabaseAuthenticationProvider.ProviderName;

        foreach (var provider in _providers)
        {
            if (owner != null && !string.Equals(provider.Name, owner, StringComparison.Ordinal))
                continue; // a stored user belongs to one provider

            var started = Stopwatch.GetTimestamp();
            AuthResult result;
            try
            {
                result = await provider.AuthenticateAsync(request, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Fail closed. The request text has no password.
                _logger.LogError(ex, "The authentication provider {Provider} failed for the {Request}; the login is refused.", provider.Name, request.ToString());
                result = AuthResult.Failure($"the authentication provider {provider.Name} failed");
            }

            switch (result.Outcome)
            {
                case AuthOutcome.NotHandled:
                    continue;
                case AuthOutcome.Failure:
                    if (request.IsPassword && !IsDatabase(provider.Name))
                        _failureTimes.GetOrAdd(provider.Name, _ => new FailureTime()).Add(Stopwatch.GetElapsedTime(started));
                    return CredentialCheck.Failed(result.Reason ?? $"refused by the authentication provider {provider.Name}", provider.Name);
                case AuthOutcome.Success:
                    var (user, needsSave, error) = _provisioner.Prepare(provider.Name, request.Username, result.User, stored);
                    if (error != null)
                    {
                        _logger.LogWarning("The authentication provider {Provider} accepted {Username}, but the user is refused: {Reason}.",
                            provider.Name, LogText.Clean(request.Username), error);
                        return CredentialCheck.Failed(error, provider.Name);
                    }
                    return new CredentialCheck(true, null, provider.Name, user, needsSave);
                default:
                    return CredentialCheck.Failed($"the authentication provider {provider.Name} gave no result", provider.Name);
            }
        }

        // No provider knows the user: the same time as a wrong password.
        if (request.IsPassword)
            UserLogics.SimulatePasswordCheck();
        return CredentialCheck.Failed(owner == null ? "unknown user" : $"the authentication provider {owner} of the user is not used");
    }

    public async ValueTask SpendFailureTimeAsync(AuthRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.IsPassword)
            return;
        // A wrong password of an external user takes the time of its provider; the provider is not asked here, so a
        // refused client learns nothing about the password.
        if (request.StoredUser?.AuthenticationProvider is { } owner && _failureTimes.TryGetValue(owner, out var time) && time.Mean is { } mean)
        {
            await Task.Delay(mean, ct);
            return;
        }
        UserLogics.SimulatePasswordCheck();
    }

    public bool Save(CredentialCheck check)
    {
        ArgumentNullException.ThrowIfNull(check);
        if (!check.Succeeded || check.User == null)
            return false;
        if (!check.NeedsSave)
            return true;
        try
        {
            return _provisioner.Save(check.User);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "User {Username} of the authentication provider {Provider} cannot be saved; the login is refused.",
                LogText.Clean(check.User.Username), check.Provider);
            return false;
        }
    }

    private static bool IsDatabase(string name) => string.Equals(name, DatabaseAuthenticationProvider.ProviderName, StringComparison.Ordinal);

    private static IReadOnlyList<IAuthenticationProvider> Order(List<IAuthenticationProvider> registered, IReadOnlyList<string> configured, ILogger logger)
    {
        var duplicate = registered.GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase).FirstOrDefault(g => g.Count() > 1);
        if (duplicate != null)
            throw new InvalidOperationException($"Two authentication providers have the name '{duplicate.Key}'.");

        if (configured.Count == 0)
            return registered.Where(p => IsDatabase(p.Name)).Concat(registered.Where(p => !IsDatabase(p.Name))).ToList();

        var ordered = new List<IAuthenticationProvider>();
        foreach (var name in configured)
        {
            var provider = registered.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))
                ?? throw new InvalidOperationException(
                    $"{AuthenticationOptions.SectionName}:Providers names '{name}', but there is no such provider. Registered: " +
                    $"{string.Join(", ", registered.Select(p => p.Name))}. Configure the provider (for example Auth:Ldap or Auth:HttpHook) or remove the name.");
            ordered.Add(provider);
        }
        foreach (var unused in registered.Except(ordered))
            logger.LogWarning("The authentication provider {Provider} is not in {Section}:Providers and is not used.", unused.Name, AuthenticationOptions.SectionName);
        return ordered;
    }

    /// <summary>A moving mean of the last durations.</summary>
    private sealed class FailureTime
    {
        private const int Samples = 16;
        private readonly Queue<TimeSpan> _values = new();
        private readonly Lock _lock = new();

        public void Add(TimeSpan value)
        {
            lock (_lock)
            {
                _values.Enqueue(value);
                if (_values.Count > Samples)
                    _values.Dequeue();
            }
        }

        public TimeSpan? Mean
        {
            get
            {
                lock (_lock)
                    return _values.Count == 0 ? null : TimeSpan.FromTicks((long)_values.Average(v => v.Ticks));
            }
        }
    }
}
