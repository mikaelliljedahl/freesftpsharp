#nullable enable
using System;
using System.Net;
using System.Security.Claims;
using FxSsh.SshServerModule.Security;
using FxSshSftpServer.Security.Oidc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Net;
using SshServer.Interfaces.Users;
using SshServerModule.Authentication;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The local user of an OpenID Connect sign-in to the web client (#73). The provider proved the identity; this class
    /// applies the rules of the server, the same as for a password login of the web client:
    /// <list type="number">
    /// <item>the global IP rules and the auto-ban;</item>
    /// <item>the user name claim and the required role;</item>
    /// <item>ownership (#64): a local user (the database) with the name signs in as itself, unchanged; a user of the
    /// sign-in (<see cref="OidcClaims.ProviderName"/>) gets its groups from the token; a user of another provider is
    /// refused; a new name is created only with <see cref="OidcSignInOptions.AutoProvision"/>, in
    /// <see cref="ClientOidcOptions.TemplateGroup"/>, by the <see cref="ExternalUserProvisioner"/> of the providers, so
    /// it has no local password;</item>
    /// <item>the lifecycle (status, expiry), the allowed networks with the groups, and the protocol flag "Web".</item>
    /// </list>
    /// The TOTP second factor of the server is not asked: the provider does the multi-factor authentication.
    /// </summary>
    public sealed class ClientOidcAccounts
    {
        private readonly ClientOidcOptions _options;
        private readonly ISettingsRepository _repository;
        private readonly ExternalUserProvisioner _provisioner;
        private readonly IEffectiveUserSettingsService _settings;
        private readonly PasswordLoginService _addresses;
        private readonly TimeProvider _time;
        private readonly ILogger<ClientOidcAccounts> _logger;

        public ClientOidcAccounts(IOptions<ClientOidcOptions> options, ISettingsRepository repository, ExternalUserProvisioner provisioner,
            IEffectiveUserSettingsService settings, PasswordLoginService addresses, TimeProvider time, ILogger<ClientOidcAccounts> logger)
        {
            _options = options.Value;
            _repository = repository;
            _provisioner = provisioner;
            _settings = settings;
            _addresses = addresses;
            _time = time;
            _logger = logger;
        }

        /// <summary>The user to sign in, or the refusal. A new or changed user is saved here.</summary>
        public OidcAccountResult<User> Resolve(ClaimsPrincipal external, IPAddress remote)
        {
            ArgumentNullException.ThrowIfNull(external);
            ArgumentNullException.ThrowIfNull(remote);
            var address = CidrNotation.Normalize(remote);
            if (_addresses.CheckAddress(address) is var filter && filter != FxSsh.SshServerModule.Security.IpFilterResult.Allowed)
                return Refused(OidcRefusal.AddressRefused, null, $"the address {address} is {filter.ToString().ToLowerInvariant()}");

            var username = OidcClaims.Username(external, _options.UsernameClaim);
            if (username == null)
                return Refused(OidcRefusal.NoUsername, null, $"the token has no claim {_options.UsernameClaim}");
            if (!OidcClaims.HasRequiredRole(external, _options))
                return Refused(OidcRefusal.MissingRole, username, $"the claim {_options.RoleClaim} does not have the value {_options.RequiredRoleValue}");

            var stored = _repository.GetUser(username);
            if (stored == null && !_options.AutoProvision)
                return Refused(OidcRefusal.UnknownAccount, username, "no user has the name and AutoProvision is off");
            if (stored?.AuthenticationProvider is { } owner && !string.Equals(owner, OidcClaims.ProviderName, StringComparison.Ordinal))
                return Refused(OidcRefusal.AccountNotUsable, username, $"the user belongs to the authentication provider {owner}");

            // A local user stays as the administrator made it; a user of the sign-in follows the groups of the token.
            ExternalUser? definition = null;
            if (stored == null || stored.AuthenticationProvider != null)
            {
                definition = new ExternalUser
                {
                    PrimaryGroup = stored == null && !string.IsNullOrWhiteSpace(_options.TemplateGroup) ? _options.TemplateGroup.Trim() : null,
                    Groups = OidcClaims.Groups(external, _options),
                };
            }

            var (user, needsSave, error) = _provisioner.Prepare(OidcClaims.ProviderName, username, definition, stored);
            if (user == null)
                return Refused(OidcRefusal.AccountNotUsable, username, error ?? "the user cannot be prepared");

            if (UserLoginRules.Refusal(user, AuthMethods.None, _time.GetUtcNow().UtcDateTime, 0) is { } lifecycle)
                return Refused(OidcRefusal.AccountRefused, username, lifecycle);
            var allowed = _settings.Resolve(user).AllowedIps;
            if (allowed.Count > 0 && !CidrNotation.Contains(CidrNotation.ParseValid(allowed), address))
                return Refused(OidcRefusal.AccountRefused, username, "the address is not in the whitelist of the user");
            if (!user.AllowedProtocols.Allows(UserProtocols.Web))
                return Refused(OidcRefusal.AccountRefused, username, "the protocol is not allowed for the user");

            if (needsSave && !_provisioner.Save(user))
                return Refused(OidcRefusal.AccountNotUsable, username, "the user of the sign-in cannot be saved");
            if (needsSave)
                user = _repository.GetUser(username) ?? user;
            return OidcAccountResult<User>.Ok(user);
        }

        private OidcAccountResult<User> Refused(OidcRefusal refusal, string? username, string reason)
        {
            _logger.LogWarning("OpenID Connect sign-in of {Username} to the web client refused: {Reason}.", LogText.Clean(username) ?? "?", LogText.Clean(reason));
            return OidcAccountResult<User>.Refused(refusal, reason);
        }
    }
}
