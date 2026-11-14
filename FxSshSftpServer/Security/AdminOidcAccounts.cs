#nullable enable
using System;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.SshServerModule.Security;
using FxSshSftpServer.Security.Oidc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Admins;

namespace FxSshSftpServer.Security
{
    /// <summary>
    /// The administrator of an OpenID Connect sign-in to the admin UI (#73). The claim <see cref="OidcSignInOptions.UsernameClaim"/>
    /// names the administrator; it must exist, or with <see cref="OidcSignInOptions.AutoProvision"/> it is created with
    /// the permissions of its role values (<see cref="AdminOidcOptions.RolePermissions"/>) and the scope role whose name
    /// is one of its role values. Then the same rules as for a password login: enabled, and from an allowed network.
    /// </summary>
    public sealed class AdminOidcAccounts
    {
        /// <summary>The actor of the administrators that the sign-in creates, in the audit log.</summary>
        public static readonly AdminActor ProvisioningActor = new(OidcClaims.ProviderName, AdminPermissionRules.Everything, null);

        private readonly AdminOidcOptions _options;
        private readonly IAdminStore _store;
        private readonly AdminAdministrationService _administration;
        private readonly ILogger<AdminOidcAccounts> _logger;

        public AdminOidcAccounts(IOptions<AdminOidcOptions> options, IAdminStore store, AdminAdministrationService administration,
            ILogger<AdminOidcAccounts> logger)
        {
            _options = options.Value;
            _store = store;
            _administration = administration;
            _logger = logger;
        }

        /// <summary>The administrator to sign in, or the refusal.</summary>
        public async Task<OidcAccountResult<Admin>> ResolveAsync(ClaimsPrincipal external, IPAddress? remote, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(external);
            var username = OidcClaims.Username(external, _options.UsernameClaim);
            if (username == null)
                return Refused(OidcRefusal.NoUsername, null, $"the token has no claim {_options.UsernameClaim}");
            if (!OidcClaims.HasRequiredRole(external, _options))
                return Refused(OidcRefusal.MissingRole, username, $"the claim {_options.RoleClaim} does not have the value {_options.RequiredRoleValue}");

            var admin = await _store.GetAdminAsync(username, ct);
            if (admin == null)
            {
                if (!_options.AutoProvision)
                    return Refused(OidcRefusal.UnknownAccount, username, "no administrator has the name and AutoProvision is off");
                var created = await CreateAsync(external, username, ct);
                if (created.Account == null)
                    return created;
                admin = created.Account;
            }

            if (admin.Status != AdminStatus.Enabled)
                return Refused(OidcRefusal.AccountRefused, username, "the administrator is disabled");
            if (!AdminClaims.IsAddressAllowed(admin, remote!))
                return Refused(OidcRefusal.AccountRefused, username, "the address is not allowed for the administrator");
            return OidcAccountResult<Admin>.Ok(admin);
        }

        private async Task<OidcAccountResult<Admin>> CreateAsync(ClaimsPrincipal external, string username, CancellationToken ct)
        {
            var values = OidcClaims.Values(external, _options.RoleClaim);
            var map = _options.ParseRolePermissions();
            var permissions = values.Aggregate(AdminPermissions.None, (all, v) => map.TryGetValue(v, out var p) ? all | p : all);
            if (permissions == AdminPermissions.None)
                return Refused(OidcRefusal.MissingRole, username, $"no value of the claim {_options.RoleClaim} is in RolePermissions");

            var roles = await _store.ListRolesAsync(ct);
            var scope = values.Select(v => roles.FirstOrDefault(r => string.Equals(r.Name, v, StringComparison.OrdinalIgnoreCase))).FirstOrDefault(r => r != null);
            try
            {
                // The administrator has no usable local password: a random one that nobody knows (the sign-in is its login).
                var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                var admin = await _administration.CreateAdminAsync(ProvisioningActor,
                    new AdminInput(username) { Permissions = permissions, ScopeRoleId = scope?.Id }, password, ct);
                _logger.LogInformation("Created administrator {Username} from the OpenID Connect sign-in with {Permissions}{Scope}.",
                    LogText.Clean(username), permissions, scope == null ? "" : " in the scope role " + LogText.Clean(scope.Name));
                return OidcAccountResult<Admin>.Ok(admin);
            }
            catch (AdminAdministrationException ex)
            {
                // Another sign-in created it at the same time: use that one.
                if (await _store.GetAdminAsync(username, ct) is { } existing)
                    return OidcAccountResult<Admin>.Ok(existing);
                return Refused(OidcRefusal.AccountNotUsable, username, "the administrator cannot be created: " + ex.Message);
            }
        }

        private OidcAccountResult<Admin> Refused(OidcRefusal refusal, string? username, string reason)
        {
            _logger.LogWarning("OpenID Connect sign-in of {Username} to the admin UI refused: {Reason}.", LogText.Clean(username) ?? "?", LogText.Clean(reason));
            return OidcAccountResult<Admin>.Refused(refusal, reason);
        }
    }
}
