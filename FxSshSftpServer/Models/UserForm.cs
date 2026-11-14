using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Users;
using SshServer.Interfaces;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using System.Linq;
using SshServer.Interfaces.Security;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using SshServerModule.Storage;

namespace FxSshSftpServer.Models
{
    /// <summary>The add/edit form of an SFTP user.</summary>
    public sealed class UserForm : IValidatableObject
    {
        public const int MinimumPasswordLength = UserAdministrationService.MinimumPasswordLength;

        /// <summary>True for a user that is not saved yet. The user name of a saved user cannot change (the repository finds users by name).</summary>
        public bool IsNew { get; set; }

        /// <summary>The external authentication provider that owns the user (#64, read-only), or null for a local user.</summary>
        public string AuthenticationProvider { get; set; }

        [Required(ErrorMessage = "Enter a user name.")]
        [StringLength(UserAdministrationService.MaximumUserNameLength, ErrorMessage = "The user name can have at most 100 characters.")]
        [RegularExpression(UserAdministrationService.UserNamePattern, ErrorMessage = "The user name cannot have spaces, ':', '/' or '\\'.")]
        public string Username { get; set; } = "";

        /// <summary>The local root directory of the default storage; required only while <see cref="Storage"/> has no provider.</summary>
        public string UserRootDirectory { get; set; } = "";

        /// <summary>The storage of "/" (issue #56). No provider: the default storage, the local disk at <see cref="UserRootDirectory"/>.</summary>
        public StorageSettings Storage { get; set; } = new();

        /// <summary>The virtual folders mounted for the user (issue #56).</summary>
        public List<MountRow> Mounts { get; set; } = new();

        public bool UsesDefaultStorage => string.IsNullOrEmpty(Storage.Provider);

        /// <summary>A new password. Empty: keep the stored password.</summary>
        public string NewPassword { get; set; } = "";

        public string ConfirmPassword { get; set; } = "";

        /// <summary>Removes the stored password (for a user that logs in with a key only).</summary>
        public bool RemovePassword { get; set; }

        public bool OnlyWhitelistedIps { get; set; }

        [CidrList]
        public string WhitelistedIps { get; set; } = "";

        public bool HasPassword { get; set; }

        /// <summary>The stored keys, for display. The page changes them at once through <see cref="UserAdministrationService"/>, not with Save.</summary>
        public List<PublicKeyEntry> PublicKeys { get; set; } = new();

        /// <summary>The value of <see cref="MultiStep"/> for [PublicKey, Password].</summary>
        public const string KeyThenPassword = "publickey,password";

        /// <summary>The value of <see cref="MultiStep"/> for [Password, PublicKey].</summary>
        public const string PasswordThenKey = "password,publickey";

        /// <summary>The value of <see cref="MultiStep"/> for [PublicKey, KeyboardInteractive] (the key, then the TOTP code, #63).</summary>
        public const string KeyThenKeyboardInteractive = "publickey,keyboard-interactive";

        public bool AllowPassword { get; set; } = true;

        public bool AllowPublicKey { get; set; } = true;

        /// <summary>The allowed methods that the form does not show (keyboard-interactive, #63); they are kept as stored.</summary>
        public AuthMethods OtherAllowedMethods { get; set; } = AuthMethods.KeyboardInteractive;

        /// <summary>Empty (one method is enough), <see cref="KeyThenPassword"/>, <see cref="PasswordThenKey"/> or <see cref="KeyThenKeyboardInteractive"/>.</summary>
        public string MultiStep { get; set; } = "";

        public DateTime? LastLoginAt { get; set; }

        /// <summary>A note of the administrator.</summary>
        [StringLength(1000, ErrorMessage = "The description can have at most 1000 characters.")]
        public string Description { get; set; } = "";

        /// <summary>The user may log in (<see cref="UserStatus.Enabled"/>).</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>The day (UTC) from which the user cannot log in; null: never. The user expires at 00:00 UTC of that day.</summary>
        public DateTime? ExpiresOn { get; set; }

        [Range(0, 10_000, ErrorMessage = "The session limit must be from 0 to 10000 (0: no limit).")]
        public int MaxSessions { get; set; }

        /// <summary>The time the password was set (display only).</summary>
        public DateTime? PasswordChangedAt { get; set; }

        /// <summary>The primary group (issue #61); 0: none.</summary>
        public int PrimaryGroupId { get; set; }

        /// <summary>
        /// The secondary groups in their order. The page toggles only the groups that the administrator sees, so a group
        /// outside its scope stays as it is.
        /// </summary>
        public List<int> SecondaryGroupIds { get; set; } = new();

        public bool HasGroups => PrimaryGroupId != 0 || SecondaryGroupIds.Count > 0;

        /// <summary>
        /// For a user with groups: no own permissions and path filters, the groups give them. Without groups the tables
        /// are always shown; "/" with every permission and no filter is then the same as not set.
        /// </summary>
        public bool InheritPermissions { get; set; }

        /// <summary>A selected group has a storage template, so the user needs no root directory (set by the page).</summary>
        public bool GroupProvidesStorage { get; set; }

        public bool UsesOwnPermissions => !HasGroups || !InheritPermissions;

        /// <summary>The user may log in with SFTP (issue #71).</summary>
        public bool AllowSftp { get; set; } = true;

        /// <summary>The user may log in with WebDAV (issue #71), when WebDAV is on for the server.</summary>
        public bool AllowWebDav { get; set; } = true;

        /// <summary>The user may log in to the web client (issue #69), when the web client is on for the server.</summary>
        public bool AllowWeb { get; set; } = true;

        /// <summary>The stored app passwords, for display. The page changes them at once through <see cref="UserAdministrationService"/>, not with Save.</summary>
        public List<AppPassword> AppPasswords { get; set; } = new();

        /// <summary>The permissions per directory (issue #59); the first row is always "/".</summary>
        public List<PermissionRow> Permissions { get; set; } = new() { PermissionRow.Root() };

        /// <summary>The path filters per directory (issue #59).</summary>
        public List<PathFilterRow> PathFilters { get; set; } = new();

        /// <summary>The quotas and the bandwidth of the user (issue #62); not set: unlimited, or the values of its groups.</summary>
        public QuotaForm Quotas { get; set; } = new();

        public static UserForm New() => new() { IsNew = true };

        public static UserForm From(User user, StorageConfigService storage) => new()
        {
            Storage = storage.Edit(user.Storage),
            Mounts = (user.VirtualFolders ?? new List<VirtualFolderMount>())
                .OrderBy(m => m.MountPath, StringComparer.Ordinal)
                .Select(MountRow.From)
                .ToList(),
            Quotas = QuotaForm.From(user.DiskQuota, user.TransferQuota, user.Bandwidth),
            IsNew = false,
            Username = user.Username ?? "",
            UserRootDirectory = user.UserRootDirectory ?? "",
            OnlyWhitelistedIps = user.OnlyWhitelistedIps,
            WhitelistedIps = EntryList.Format(user.WhitelistedIps),
            HasPassword = !string.IsNullOrWhiteSpace(user.HashedPassword),
            PublicKeys = user.PublicKeys?.ToList() ?? new List<PublicKeyEntry>(),
            AllowPassword = user.AllowedAuthMethods.HasFlag(AuthMethods.Password),
            AllowPublicKey = user.AllowedAuthMethods.HasFlag(AuthMethods.PublicKey),
            OtherAllowedMethods = user.AllowedAuthMethods & ~(AuthMethods.Password | AuthMethods.PublicKey),
            MultiStep = MultiStepOf(user.RequireAllOf),
            AllowSftp = user.AllowedProtocols.Allows(UserProtocols.Sftp),
            AllowWebDav = user.AllowedProtocols.Allows(UserProtocols.WebDav),
            AllowWeb = user.AllowedProtocols.Allows(UserProtocols.Web),
            AppPasswords = user.AppPasswords?.ToList() ?? new List<AppPassword>(),
            LastLoginAt = user.LastLoginAt,
            Description = user.Description ?? "",
            Enabled = user.Status == UserStatus.Enabled,
            ExpiresOn = user.ExpiresAt?.Date,
            MaxSessions = user.MaxSessions,
            AuthenticationProvider = user.AuthenticationProvider,
            PasswordChangedAt = user.PasswordChangedAt,
            PrimaryGroupId = user.PrimaryGroupId ?? 0,
            SecondaryGroupIds = (user.SecondaryGroupIds ?? new List<int>()).ToList(),
            InheritPermissions = user.Permissions is not { Count: > 0 } && (user.PathFilters is null || user.PathFilters.Values.All(f => f.IsEmpty)),
            Permissions = PermissionTables.RowsOf(user.Permissions),
            PathFilters = PermissionTables.FilterRowsOf(user.PathFilters),
        };

        private static string MultiStepOf(List<AuthMethods> steps) =>
            steps is { Count: > 0 } ? string.Join(",", steps.Select(AuthMethodRules.ToSshName)) : "";

        private AuthMethods AllowedMethods =>
            (AllowPassword ? AuthMethods.Password : AuthMethods.None) | (AllowPublicKey ? AuthMethods.PublicKey : AuthMethods.None) | OtherAllowedMethods;

        private UserProtocols AllowedProtocols =>
            (AllowSftp ? UserProtocols.Sftp : UserProtocols.None) | (AllowWebDav ? UserProtocols.WebDav : UserProtocols.None)
            | (AllowWeb ? UserProtocols.Web : UserProtocols.None);

        private List<AuthMethods> RequiredSteps => MultiStep switch
        {
            KeyThenPassword => new List<AuthMethods> { AuthMethods.PublicKey, AuthMethods.Password },
            PasswordThenKey => new List<AuthMethods> { AuthMethods.Password, AuthMethods.PublicKey },
            KeyThenKeyboardInteractive => new List<AuthMethods> { AuthMethods.PublicKey, AuthMethods.KeyboardInteractive },
            _ => null,
        };

        /// <summary>
        /// Writes the form to <paramref name="user"/> (a new user, or the stored copy of an existing one). A new
        /// password is hashed with <see cref="PasswordHasher"/>; the plain text never leaves the form.
        /// </summary>
        /// <remarks>The storage configuration is built and validated by <see cref="StorageConfigService"/>; the caller sets <see cref="User.Storage"/>.</remarks>
        /// <param name="utcNow">The time of a new password (<see cref="User.PasswordChangedAt"/>). Null: now.</param>
        public void ApplyTo(User user, int passwordIterations = PasswordHasher.DefaultIterations, DateTime? utcNow = null)
        {
            ApplySettingsTo(user);
            if (!string.IsNullOrEmpty(NewPassword))
            {
                user.HashedPassword = PasswordHasher.Hash(NewPassword, passwordIterations);
                user.PasswordChangedAt = utcNow ?? DateTime.UtcNow;
            }
            else if (RemovePassword)
            {
                user.HashedPassword = null;
                user.PasswordChangedAt = null;
            }
        }

        /// <summary>Writes every field except the password: also for the preview of the effective settings.</summary>
        public void ApplySettingsTo(User user)
        {
            if (IsNew)
                user.Username = Username.Trim();
            user.UserRootDirectory = UserRootDirectory.Trim();
            user.VirtualFolders = MountList();
            user.OnlyWhitelistedIps = OnlyWhitelistedIps;
            user.WhitelistedIps = EntryList.Parse(WhitelistedIps);
            user.AllowedAuthMethods = AllowedMethods;
            user.RequireAllOf = RequiredSteps;
            user.AllowedProtocols = AllowedProtocols; // every protocol ticked is stored as "All"
            if (UsesOwnPermissions)
            {
                // Without groups, "/" = All and no filter is the same as not set; then a group can give them later.
                user.Permissions = !HasGroups && PermissionTables.IsRootAllOnly(Permissions) ? null : PermissionTables.ToDictionary(Permissions);
                user.PathFilters = PermissionTables.NonEmptyFilters(PathFilters);
            }
            else
            {
                user.Permissions = null;
                user.PathFilters = null;
            }
            user.Description = string.IsNullOrWhiteSpace(Description) ? null : Description.Trim();
            user.Status = Enabled ? UserStatus.Enabled : UserStatus.Disabled;
            user.ExpiresAt = ExpiresOn is { } day ? DateTime.SpecifyKind(day.Date, DateTimeKind.Utc) : null;
            user.MaxSessions = MaxSessions;
            user.PrimaryGroupId = PrimaryGroupId == 0 ? null : PrimaryGroupId;
            user.SecondaryGroupIds = SecondaryGroupIds.Where(id => id != PrimaryGroupId).Distinct().ToList();
            user.DiskQuota = Quotas.Disk;
            user.TransferQuota = Quotas.Transfer;
            user.Bandwidth = Quotas.Bandwidth;
        }

        /// <summary>The mounts of the form, with normalized paths.</summary>
        public List<VirtualFolderMount> MountList() => Mounts.Select(m => m.ToMount()).ToList();

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (UsesDefaultStorage && !GroupProvidesStorage && string.IsNullOrWhiteSpace(UserRootDirectory))
                yield return new ValidationResult("Enter the root directory of the user on the server.", new[] { nameof(UserRootDirectory) });

            if (!string.IsNullOrEmpty(NewPassword))
            {
                if (NewPassword.Length < MinimumPasswordLength)
                    yield return new ValidationResult($"The password must have at least {MinimumPasswordLength} characters.", new[] { nameof(NewPassword) });
                if (!string.Equals(NewPassword, ConfirmPassword, StringComparison.Ordinal))
                    yield return new ValidationResult("The passwords are not the same.", new[] { nameof(ConfirmPassword) });
            }

            if (!AllowPassword && !AllowPublicKey)
                yield return new ValidationResult("Allow the password, the public key or both.", new[] { nameof(AllowPassword) });
            else
                foreach (var problem in AuthMethodRules.Validate(AllowedMethods, RequiredSteps))
                    yield return new ValidationResult(problem, new[] { nameof(AllowPassword) });

            if (!AllowSftp && !AllowWebDav && !AllowWeb)
                yield return new ValidationResult("Allow at least one protocol.", new[] { nameof(AllowSftp) });

            foreach (var problem in Quotas.Problems(Mounts))
                yield return new ValidationResult(problem, new[] { nameof(Quotas) });

            if (!UsesOwnPermissions)
                yield break;
            var (permissionProblems, filterProblems) = PermissionTables.Problems(Permissions, PathFilters);
            foreach (var problem in permissionProblems)
                yield return new ValidationResult(problem, new[] { nameof(Permissions) });
            foreach (var problem in filterProblems)
                yield return new ValidationResult(problem, new[] { nameof(PathFilters) });
        }
    }
}
