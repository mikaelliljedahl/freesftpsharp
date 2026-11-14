#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Admins;

namespace FxSshSftpServer.Security.Oidc
{
    /// <summary>
    /// One OpenID Connect sign-in (#73): <c>Auth:Oidc:Admin</c> for the admin UI (<see cref="AdminOidcOptions"/>) or
    /// <c>Auth:Oidc:Client</c> for the web client (<see cref="ClientOidcOptions"/>). Off while <see cref="Authority"/> is
    /// empty: then no handler is registered and the login pages look as before.
    /// </summary>
    public abstract class OidcSignInOptions
    {
        /// <summary>The issuer, for example <c>https://keycloak.example.org/realms/sftp</c>. Empty: this sign-in is off.</summary>
        public string? Authority { get; set; }

        public string? ClientId { get; set; }

        /// <summary>The secret of a confidential client. Empty: a public client (the code flow still uses PKCE).</summary>
        public string? ClientSecret { get; set; }

        /// <summary>The scopes besides <c>openid</c>. Default: <c>profile</c>.</summary>
        public List<string> Scopes { get; set; } = new();

        /// <summary>The claim with the local user name (<c>Admin.Username</c> or <c>User.Username</c>).</summary>
        public string UsernameClaim { get; set; } = "preferred_username";

        /// <summary>
        /// The claim with the roles of the account, for example <c>roles</c> (Entra ID app roles, a Keycloak mapper) or the
        /// path <c>realm_access.roles</c> (the default Keycloak access token layout).
        /// </summary>
        public string RoleClaim { get; set; } = "roles";

        /// <summary>A value that <see cref="RoleClaim"/> must have. Empty: every account of the provider may sign in.</summary>
        public string? RequiredRoleValue { get; set; }

        /// <summary>Create an account at its first sign-in. Default false: the account must exist.</summary>
        public bool AutoProvision { get; set; }

        /// <summary>The text of the button: "Sign in with <see cref="DisplayName"/>".</summary>
        public string DisplayName { get; set; } = "single sign-on";

        /// <summary>Remove the password form; <c>POST</c> of the login page answers 404. Turn it on when the sign-in works.</summary>
        public bool DisableLocalLogin { get; set; }

        /// <summary>The discovery document and the keys only over HTTPS. Turn it off only for a test provider on this host.</summary>
        public bool RequireHttpsMetadata { get; set; } = true;

        public bool IsEnabled => !string.IsNullOrWhiteSpace(Authority);

        /// <summary>The scopes of the request: <c>openid</c>, then <see cref="Scopes"/> (or <c>profile</c>).</summary>
        public IReadOnlyList<string> EffectiveScopes()
        {
            var scopes = Scopes.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToList();
            if (scopes.Count == 0)
                scopes.Add("profile");
            return new[] { "openid" }.Concat(scopes).Distinct(StringComparer.Ordinal).ToList();
        }

        /// <summary>The errors of this section; empty when it is off or valid.</summary>
        public virtual List<string> Validate(string section)
        {
            var errors = new List<string>();
            if (!IsEnabled)
                return errors;
            if (!Uri.TryCreate(Authority, UriKind.Absolute, out var authority) || (authority.Scheme != Uri.UriSchemeHttps && authority.Scheme != Uri.UriSchemeHttp))
                errors.Add($"{section}:Authority must be an absolute http(s) URL.");
            else if (RequireHttpsMetadata && authority.Scheme != Uri.UriSchemeHttps)
                errors.Add($"{section}:Authority must use https (or set {section}:RequireHttpsMetadata to false for a test provider).");
            if (string.IsNullOrWhiteSpace(ClientId))
                errors.Add($"{section}:ClientId is required.");
            if (string.IsNullOrWhiteSpace(UsernameClaim))
                errors.Add($"{section}:UsernameClaim must not be empty.");
            if (!string.IsNullOrWhiteSpace(RequiredRoleValue) && string.IsNullOrWhiteSpace(RoleClaim))
                errors.Add($"{section}:RoleClaim is required with RequiredRoleValue.");
            return errors;
        }
    }

    /// <summary>The section <c>Auth:Oidc:Admin</c>: the sign-in of the administrators (#60).</summary>
    public sealed class AdminOidcOptions : OidcSignInOptions
    {
        public const string SectionName = "Auth:Oidc:Admin";

        /// <summary>
        /// For <see cref="OidcSignInOptions.AutoProvision"/>: the permissions of a new administrator per value of
        /// <see cref="OidcSignInOptions.RoleClaim"/>, as a comma separated list of <see cref="AdminPermissions"/> names,
        /// for example <c>{ "sftp-helpdesk": "ViewConnections, ViewAudit" }</c>. A new administrator gets the union of
        /// the values it has; one without a mapped value is refused. A value that is the name of a scope role makes
        /// that role its scope.
        /// </summary>
        public Dictionary<string, string> RolePermissions { get; set; } = new(StringComparer.Ordinal);

        /// <summary>The permissions of the role values, or the errors of their names.</summary>
        public Dictionary<string, AdminPermissions> ParseRolePermissions(List<string>? errors = null)
        {
            var parsed = new Dictionary<string, AdminPermissions>(StringComparer.Ordinal);
            foreach (var (role, text) in RolePermissions)
            {
                var permissions = AdminPermissions.None;
                foreach (var name in (text ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (Enum.TryParse<AdminPermissions>(name, ignoreCase: true, out var flag) && Enum.IsDefined(flag) && !int.TryParse(name, out _))
                        permissions |= flag;
                    else
                        errors?.Add($"{SectionName}:RolePermissions:{role} has the unknown permission '{name}'.");
                }
                parsed[role] = permissions;
            }
            return parsed;
        }

        public override List<string> Validate(string section)
        {
            var errors = base.Validate(section);
            if (!IsEnabled)
                return errors;
            var parsed = ParseRolePermissions(errors);
            if (AutoProvision && !parsed.Values.Any(p => p != AdminPermissions.None))
                errors.Add($"{section}:AutoProvision needs {section}:RolePermissions (role value -> permissions).");
            if (AutoProvision && string.IsNullOrWhiteSpace(RoleClaim))
                errors.Add($"{section}:AutoProvision needs {section}:RoleClaim.");
            return errors;
        }
    }

    /// <summary>The section <c>Auth:Oidc:Client</c>: the sign-in of the SFTP users to the web client (#69).</summary>
    public sealed class ClientOidcOptions : OidcSignInOptions
    {
        public const string SectionName = "Auth:Oidc:Client";

        /// <summary>The primary group (#61) of a user that <see cref="OidcSignInOptions.AutoProvision"/> creates: the template with the storage and the permissions.</summary>
        public string? TemplateGroup { get; set; }

        /// <summary>The claim with the groups of the account. Empty: the groups are not mapped.</summary>
        public string? GroupsClaim { get; set; } = "groups";

        /// <summary>
        /// Group of the provider -> local group. Empty: a group of the provider is the local group with the same name. A
        /// group without a local group is skipped.
        /// </summary>
        public Dictionary<string, string> GroupMap { get; set; } = new(StringComparer.Ordinal);
    }

    /// <summary>Checks both sections at the start (<c>ValidateOnStart</c>).</summary>
    public sealed class OidcSignInOptionsValidator : IValidateOptions<AdminOidcOptions>, IValidateOptions<ClientOidcOptions>
    {
        public ValidateOptionsResult Validate(string? name, AdminOidcOptions options) => Result(options.Validate(AdminOidcOptions.SectionName));

        public ValidateOptionsResult Validate(string? name, ClientOidcOptions options) => Result(options.Validate(ClientOidcOptions.SectionName));

        private static ValidateOptionsResult Result(List<string> errors) =>
            errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
