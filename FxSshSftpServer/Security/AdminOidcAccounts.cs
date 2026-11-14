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
    /// is one of its role values. The administrators that it creates belong to the provider <c>oidc</c>
    /// (<see cref="Admin.AuthenticationProvider"/>, #145): they have no local password, and with
    /// <see cref="AdminOidcOptions.SyncRolesOnSignIn"/> their permissions follow the role values at each sign-in. While no
    /// administrator exists, <see cref="AdminOidcOptions.BootstrapAdmin"/> is created as a super admin. Then the same rules
    /// as for a password login: enabled, and from an allowed network.
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
                OidcAccountResult<Admin> created;
                if (_options.IsBootstrapAdmin(username) && !await _store.AnyAdminAsync(ct))
                    created = await CreateBootstrapAsync(username, ct);
                else if (!_options.AutoProvision)
                    return Refused(OidcRefusal.UnknownAccount, username, "no administrator has the name and AutoProvision is off");
                else
                    created = await CreateAsync(external, username, ct);
                if (created.Account == null)
                    return created;
                admin = created.Account;
            }
            else if (_options.SyncRolesOnSignIn && string.Equals(admin.AuthenticationProvider, OidcClaims.ProviderName, StringComparison.Ordinal))
            {
                var synced = await SyncAsync(external, admin, ct);
                if (synced.Account == null)
                    return synced;
                admin = synced.Account;
            }

            if (admin.Status != AdminStatus.Enabled)
                return Refused(OidcRefusal.AccountRefused, username, "the administrator is disabled");
            if (!AdminClaims.IsAddressAllowed(admin, remote!))
                return Refused(OidcRefusal.AccountRefused, username, "the address is not allowed for the administrator");
            return OidcAccountResult<Admin>.Ok(admin);
        }

        /// <summary>The permissions of the role values of the token, and the scope role whose name is one of them.</summary>
        private async Task<(AdminPermissions Permissions, int? ScopeRoleId, Role? Scope)> MapRolesAsync(ClaimsPrincipal external, CancellationToken ct)
        {
            var values = OidcClaims.Values(external, _options.RoleClaim);
            var map = _options.ParseRolePermissions();
            var permissions = values.Aggregate(AdminPermissions.None, (all, v) => map.TryGetValue(v, out var p) ? all | p : all);
            var roles = await _store.ListRolesAsync(ct);
            var scope = values.Select(v => roles.FirstOrDefault(r => string.Equals(r.Name, v, StringComparison.OrdinalIgnoreCase))).FirstOrDefault(r => r != null);
            return (permissions, scope?.Id, scope);
        }

        private async Task<OidcAccountResult<Admin>> CreateAsync(ClaimsPrincipal external, string username, CancellationToken ct)
        {
            var (permissions, scopeId, scope) = await MapRolesAsync(external, ct);
            if (permissions == AdminPermissions.None)
                return Refused(OidcRefusal.MissingRole, username, $"no value of the claim {_options.RoleClaim} is in RolePermissions");
            var created = await AddAsync(new AdminInput(username) { Permissions = permissions, ScopeRoleId = scopeId }, ct);
            if (created.Account != null && created.Account.AuthenticationProvider == OidcClaims.ProviderName)
                _logger.LogInformation("Created administrator {Username} from the OpenID Connect sign-in with {Permissions}{Scope}.",
                    LogText.Clean(username), permissions, scope == null ? "" : " in the scope role " + LogText.Clean(scope.Name));
            return created;
        }

        /// <summary>
        /// The first administrator of an installation (<see cref="AdminOidcOptions.BootstrapAdmin"/>, #145): a super admin,
        /// only while no administrator exists.
        /// </summary>
        private async Task<OidcAccountResult<Admin>> CreateBootstrapAsync(string username, CancellationToken ct)
        {
            var created = await AddAsync(new AdminInput(username) { Permissions = AdminPermissions.SuperAdmin }, ct);
            if (created.Account != null)
                _logger.LogWarning("Created the first administrator {Username} as a super admin from the OpenID Connect sign-in ({Setting}). " +
                    "Remove the setting now: it is not used while an administrator exists.", LogText.Clean(username), AdminOidcOptions.SectionName + ":BootstrapAdmin");
            return created;
        }

        private async Task<OidcAccountResult<Admin>> AddAsync(AdminInput input, CancellationToken ct)
        {
            try
            {
                // The administrator has no usable local password: a random one that nobody knows, and the provider owns it (#145).
                var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                var admin = await _administration.CreateAdminAsync(ProvisioningActor, input with { AuthenticationProvider = OidcClaims.ProviderName }, password, ct);
                return OidcAccountResult<Admin>.Ok(admin);
            }
            catch (AdminAdministrationException ex)
            {
                // Another sign-in created it at the same time: use that one.
                if (await _store.GetAdminAsync(input.Username, ct) is { } existing)
                    return OidcAccountResult<Admin>.Ok(existing);
                return Refused(OidcRefusal.AccountNotUsable, input.Username, "the administrator cannot be created: " + ex.Message);
            }
        }

        /// <summary>
        /// <see cref="AdminOidcOptions.SyncRolesOnSignIn"/> (#145): the permissions and the scope of an administrator of the
        /// sign-in follow the role values of the token. Without a mapped value the sign-in is refused.
        /// </summary>
        private async Task<OidcAccountResult<Admin>> SyncAsync(ClaimsPrincipal external, Admin admin, CancellationToken ct)
        {
            var (permissions, scopeId, _) = await MapRolesAsync(external, ct);
            if (permissions == AdminPermissions.None)
                return Refused(OidcRefusal.MissingRole, admin.Username, $"no value of the claim {_options.RoleClaim} is in RolePermissions");
            if (permissions == admin.Permissions && scopeId == admin.ScopeRoleId)
                return OidcAccountResult<Admin>.Ok(admin);
            try
            {
                var updated = await _administration.UpdateAdminAsync(ProvisioningActor,
                    AdminInput.From(admin) with { Permissions = permissions, ScopeRoleId = scopeId }, null, ct);
                _logger.LogInformation("Updated the permissions of administrator {Username} from the OpenID Connect sign-in: {Before} -> {After}.",
                    LogText.Clean(admin.Username), admin.Permissions, permissions);
                return OidcAccountResult<Admin>.Ok(updated);
            }
            catch (Exception ex) when (ex is AdminAdministrationException or AdminAccessDeniedException)
            {
                return Refused(OidcRefusal.AccountNotUsable, admin.Username, "the permissions of the administrator cannot be updated: " + ex.Message);
            }
        }

        private OidcAccountResult<Admin> Refused(OidcRefusal refusal, string? username, string reason)
        {
            _logger.LogWarning("OpenID Connect sign-in of {Username} to the admin UI refused: {Reason}.", LogText.Clean(username) ?? "?", LogText.Clean(reason));
            return OidcAccountResult<Admin>.Refused(refusal, reason);
        }
    }
}
