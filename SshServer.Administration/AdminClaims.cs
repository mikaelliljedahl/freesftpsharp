using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.Cookies;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Net;

namespace SshServer.Administration
{
    /// <summary>
    /// The claims of a signed-in administrator in the login cookie: the name, the effective permissions, the scope role
    /// and a stamp of the security fields. <see cref="AdminSessionValidator"/> compares the stamp with the stored
    /// administrator on every request, so a change of the password, the permissions, the scope or the status ends
    /// every session of that administrator, and the claims never give more than the database.
    /// </summary>
    public static class AdminClaims
    {
        public const string PermissionsClaim = "freesftpsharp:admin_permissions";
        public const string ScopeRoleClaim = "freesftpsharp:admin_scope_role";
        public const string StampClaim = "freesftpsharp:admin_stamp";
        public const string MustChangePasswordClaim = "freesftpsharp:admin_must_change_password";

        /// <summary>The claim of a login with a REST API key (#67): the name of the key, for the audit log.</summary>
        public const string ApiKeyClaim = "freesftpsharp:api_key";

        public static ClaimsPrincipal CreatePrincipal(Admin admin) =>
            new(new ClaimsIdentity(CreateClaims(admin), CookieAuthenticationDefaults.AuthenticationScheme));

        /// <summary>
        /// The claims of an administrator. <paramref name="narrowTo"/> limits the permissions further (the scopes of an API
        /// key); it never adds one. <paramref name="apiKeyName"/> marks a login with an API key.
        /// </summary>
        public static List<Claim> CreateClaims(Admin admin, AdminPermissions? narrowTo = null, string apiKeyName = null)
        {
            var permissions = AdminPermissionRules.Effective(admin);
            if (narrowTo is { } mask)
                permissions &= mask;
            var claims = new List<Claim>
            {
                new(ClaimTypes.Name, admin.Username),
                new(ClaimTypes.Role, "Admin"),
                new(PermissionsClaim, ((int)permissions).ToString(CultureInfo.InvariantCulture)),
                new(StampClaim, Stamp(admin)),
            };
            if (admin.ScopeRoleId is { } role)
                claims.Add(new Claim(ScopeRoleClaim, role.ToString(CultureInfo.InvariantCulture)));
            if (admin.MustChangePassword)
                claims.Add(new Claim(MustChangePasswordClaim, "true"));
            if (!string.IsNullOrEmpty(apiKeyName))
                claims.Add(new Claim(ApiKeyClaim, apiKeyName));
            return claims;
        }

        /// <summary>The actor of a principal; <see cref="AdminActor.Anonymous"/> without a valid login.</summary>
        public static AdminActor ToActor(ClaimsPrincipal user)
        {
            if (user?.Identity?.IsAuthenticated != true || string.IsNullOrEmpty(user.Identity.Name)
                || !int.TryParse(user.FindFirstValue(PermissionsClaim), NumberStyles.None, CultureInfo.InvariantCulture, out var permissions))
            {
                return AdminActor.Anonymous;
            }

            int? scope = null;
            var scopeText = user.FindFirstValue(ScopeRoleClaim);
            if (scopeText != null)
            {
                if (!int.TryParse(scopeText, NumberStyles.None, CultureInfo.InvariantCulture, out var role))
                    return AdminActor.Anonymous;
                scope = role;
            }
            // The same masking as for the stored administrator, so a claim never gives a scoped administrator more.
            return new AdminActor(user.Identity.Name, AdminPermissionRules.Effective((AdminPermissions)permissions, scope), scope)
            {
                ApiKeyName = user.FindFirstValue(ApiKeyClaim),
            };
        }

        public static bool MustChangePassword(ClaimsPrincipal user) => user?.HasClaim(MustChangePasswordClaim, "true") == true;

        /// <summary>A hash of the fields that decide what the login may do. It changes when one of them changes.</summary>
        public static string Stamp(Admin admin)
        {
            var text = string.Join('\n', admin.Id.ToString(CultureInfo.InvariantCulture), admin.Username.ToLowerInvariant(),
                admin.PasswordHash, admin.Status, (int)admin.Permissions, admin.ScopeRoleId?.ToString(CultureInfo.InvariantCulture) ?? "",
                admin.MustChangePassword, string.Join(',', admin.AllowedIps ?? new List<string>()));
            return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        }

        /// <summary>True when the administrator may log in from the address (no list: from everywhere).</summary>
        public static bool IsAddressAllowed(Admin admin, IPAddress client)
        {
            if (admin.AllowedIps == null || admin.AllowedIps.Count == 0)
                return true;
            if (client == null)
                return false;
            var networks = CidrNotation.ParseValid(admin.AllowedIps);
            return CidrNotation.Contains(networks, CidrNotation.Normalize(client));
        }
    }
}
