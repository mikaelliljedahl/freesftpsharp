using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Users;

namespace FxSshSftpServer.Models
{
    /// <summary>The add/edit form of an administrator. The rules are checked again by <see cref="AdminAdministrationService"/>.</summary>
    public sealed class AdminForm : IValidatableObject
    {
        public bool IsNew { get; set; }

        [Required(ErrorMessage = "Enter a user name.")]
        [StringLength(UserAdministrationService.MaximumUserNameLength, ErrorMessage = "The user name can have at most 100 characters.")]
        [RegularExpression(UserAdministrationService.UserNamePattern, ErrorMessage = "The user name cannot have spaces, ':', '/' or '\\'.")]
        public string Username { get; set; } = "";

        [StringLength(AdminAdministrationService.MaximumEmailLength)]
        public string Email { get; set; } = "";

        /// <summary>The password of a new administrator, or a new password. Empty on edit: keep the stored one.</summary>
        public string NewPassword { get; set; } = "";

        public string ConfirmPassword { get; set; } = "";

        public bool Enabled { get; set; } = true;

        public bool MustChangePassword { get; set; }

        public AdminPermissions Permissions { get; set; }

        public int? ScopeRoleId { get; set; }

        [CidrList]
        public string AllowedIps { get; set; } = "";

        public static AdminForm New() => new() { IsNew = true, MustChangePassword = true };

        public static AdminForm From(Admin admin) => new()
        {
            IsNew = false,
            Username = admin.Username,
            Email = admin.Email ?? "",
            Enabled = admin.Status == AdminStatus.Enabled,
            MustChangePassword = admin.MustChangePassword,
            Permissions = admin.Permissions,
            ScopeRoleId = admin.ScopeRoleId,
            AllowedIps = EntryList.Format(admin.AllowedIps),
        };

        public bool Has(AdminPermissions permission) => Permissions.HasFlag(permission);

        public void Set(AdminPermissions permission, bool on) =>
            Permissions = on ? Permissions | permission : Permissions & ~permission;

        public AdminInput ToInput() => new(Username.Trim())
        {
            Email = Email,
            Status = Enabled ? AdminStatus.Enabled : AdminStatus.Disabled,
            Permissions = Permissions,
            AllowedIps = EntryList.Parse(AllowedIps),
            ScopeRoleId = ScopeRoleId,
            MustChangePassword = MustChangePassword,
        };

        /// <summary>The password to save: required for a new administrator, null on edit when it is empty.</summary>
        public string PasswordToSave => IsNew || !string.IsNullOrEmpty(NewPassword) ? NewPassword : null;

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (IsNew || !string.IsNullOrEmpty(NewPassword))
            {
                var error = AdminAdministrationService.ValidatePassword(NewPassword);
                if (error != null)
                    yield return new ValidationResult(error, new[] { nameof(NewPassword) });
                else if (!string.Equals(NewPassword, ConfirmPassword, StringComparison.Ordinal))
                    yield return new ValidationResult("The passwords do not match.", new[] { nameof(ConfirmPassword) });
            }
            if (ScopeRoleId != null && (Permissions & ~AdminPermissionRules.Scopable) != AdminPermissions.None)
                yield return new ValidationResult(
                    "An administrator with a scope role can only manage users, groups and folders, see and close connections and read the audit log.",
                    new[] { nameof(Permissions) });
        }
    }
}
