using System;
using Microsoft.AspNetCore.Authorization;
using SshServer.Interfaces.Admins;

namespace SshServer.Administration
{
    /// <summary>
    /// One authorization policy per <see cref="AdminPermissions"/> flag, named like the flag. The pages use them with
    /// <c>[Authorize(Policy = AdminPolicies.ManageUsers)]</c>; the REST API (#67) will use the same names. The
    /// application services check the same permissions again (<see cref="CurrentAdmin"/>).
    /// </summary>
    public static class AdminPolicies
    {
        public const string SuperAdmin = nameof(AdminPermissions.SuperAdmin);
        public const string ManageUsers = nameof(AdminPermissions.ManageUsers);
        public const string ManageGroups = nameof(AdminPermissions.ManageGroups);
        public const string ManageFolders = nameof(AdminPermissions.ManageFolders);
        public const string ManageEvents = nameof(AdminPermissions.ManageEvents);
        public const string ViewConnections = nameof(AdminPermissions.ViewConnections);
        public const string DisconnectConnections = nameof(AdminPermissions.DisconnectConnections);
        public const string ViewAudit = nameof(AdminPermissions.ViewAudit);
        public const string ManageSettings = nameof(AdminPermissions.ManageSettings);
        public const string ManageAdmins = nameof(AdminPermissions.ManageAdmins);

        public static void AddAdminPolicies(this AuthorizationOptions options)
        {
            foreach (var permission in AdminPermissionRules.SingleFlags)
            {
                var required = permission;
                options.AddPolicy(PolicyName(required), policy => policy
                    .RequireAuthenticatedUser()
                    .RequireAssertion(context => AdminClaims.ToActor(context.User).Has(required)));
            }
        }

        public static string PolicyName(AdminPermissions permission) =>
            Enum.IsDefined(permission) && permission != AdminPermissions.None
                ? permission.ToString()
                : throw new ArgumentOutOfRangeException(nameof(permission), permission, "Only a single permission has a policy.");
    }
}
