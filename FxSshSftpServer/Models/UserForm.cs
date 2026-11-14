using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Users;
using SshServer.Interfaces;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Net;
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

        public bool AllowPassword { get; set; } = true;

        public bool AllowPublicKey { get; set; } = true;

        /// <summary>The allowed methods that the form does not show (keyboard-interactive, #63); they are kept as stored.</summary>
        public AuthMethods OtherAllowedMethods { get; set; } = AuthMethods.KeyboardInteractive;

        /// <summary>Empty (one method is enough), <see cref="KeyThenPassword"/> or <see cref="PasswordThenKey"/>.</summary>
        public string MultiStep { get; set; } = "";

        public DateTime LastSuccessfulLogin { get; set; }

        /// <summary>The permissions per directory (issue #59); the first row is always "/".</summary>
        public List<PermissionRow> Permissions { get; set; } = new() { PermissionRow.Root() };

        /// <summary>The path filters per directory (issue #59).</summary>
        public List<PathFilterRow> PathFilters { get; set; } = new();

        /// <summary>The disk quota of the own storage in MiB (issue #62); 0: unlimited.</summary>
        public decimal QuotaSizeMiB { get; set; }

        /// <summary>The maximum number of files of the own storage; 0: unlimited.</summary>
        public long QuotaFiles { get; set; }

        /// <summary>The transfer quota in MiB (upload, download, both together); 0: unlimited.</summary>
        public decimal UploadQuotaMiB { get; set; }

        public decimal DownloadQuotaMiB { get; set; }

        public decimal TotalQuotaMiB { get; set; }

        /// <summary>The bandwidth of a session in KiB/s; 0: unlimited.</summary>
        public int UploadKiBPerSecond { get; set; }

        public int DownloadKiBPerSecond { get; set; }

        /// <summary>Other bandwidth values for some client networks.</summary>
        public List<BandwidthOverrideRow> BandwidthOverrides { get; set; } = new();

        public const decimal BytesPerMiB = 1024 * 1024;

        public static decimal ToMiB(long bytes) => bytes / BytesPerMiB;

        public static long ToBytes(decimal mib) => (long)Math.Round(mib * BytesPerMiB, MidpointRounding.AwayFromZero);

        public static UserForm New() => new() { IsNew = true };

        public static UserForm From(User user, StorageConfigService storage) => new()
        {
            Storage = storage.Edit(user.Storage),
            Mounts = (user.VirtualFolders ?? new List<VirtualFolderMount>())
                .OrderBy(m => m.MountPath, StringComparer.Ordinal)
                .Select(m => new MountRow
                {
                    VirtualFolderId = m.VirtualFolderId,
                    MountPath = m.MountPath,
                    QuotaSizeMiB = ToMiB(m.Quota?.MaxSizeBytes ?? 0),
                    QuotaFiles = m.Quota?.MaxFiles ?? 0,
                })
                .ToList(),
            QuotaSizeMiB = ToMiB(user.DiskQuota?.MaxSizeBytes ?? 0),
            QuotaFiles = user.DiskQuota?.MaxFiles ?? 0,
            UploadQuotaMiB = ToMiB(user.TransferQuota?.MaxUploadBytes ?? 0),
            DownloadQuotaMiB = ToMiB(user.TransferQuota?.MaxDownloadBytes ?? 0),
            TotalQuotaMiB = ToMiB(user.TransferQuota?.MaxTotalBytes ?? 0),
            UploadKiBPerSecond = user.Bandwidth?.UploadKiBPerSecond ?? 0,
            DownloadKiBPerSecond = user.Bandwidth?.DownloadKiBPerSecond ?? 0,
            BandwidthOverrides = (user.Bandwidth?.Overrides ?? new List<BandwidthOverride>())
                .Select(o => new BandwidthOverrideRow
                {
                    Sources = EntryList.Format(o.Sources),
                    UploadKiBPerSecond = o.UploadKiBPerSecond,
                    DownloadKiBPerSecond = o.DownloadKiBPerSecond,
                })
                .ToList(),
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
            LastSuccessfulLogin = user.LastSuccessfulLogin,
            Permissions = PermissionRowsOf(user.Permissions),
            PathFilters = (user.PathFilters ?? new Dictionary<string, PathFilter>())
                .OrderBy(f => f.Key, StringComparer.Ordinal)
                .Select(f => PathFilterRow.From(f.Key, f.Value))
                .ToList(),
        };

        private static string MultiStepOf(List<AuthMethods> steps) =>
            steps is { Count: > 0 } ? string.Join(",", steps.Select(AuthMethodRules.ToSshName)) : "";

        private AuthMethods AllowedMethods =>
            (AllowPassword ? AuthMethods.Password : AuthMethods.None) | (AllowPublicKey ? AuthMethods.PublicKey : AuthMethods.None) | OtherAllowedMethods;

        private List<AuthMethods> RequiredSteps => MultiStep switch
        {
            KeyThenPassword => new List<AuthMethods> { AuthMethods.PublicKey, AuthMethods.Password },
            PasswordThenKey => new List<AuthMethods> { AuthMethods.Password, AuthMethods.PublicKey },
            _ => null,
        };

        /// <summary>The rows of the stored permissions: "/" first (All when it is not stored), then by path.</summary>
        private static List<PermissionRow> PermissionRowsOf(Dictionary<string, FilePermissions> permissions)
        {
            var rows = (permissions ?? new Dictionary<string, FilePermissions>())
                .Select(p => new PermissionRow { Path = p.Key, Permissions = p.Value })
                .ToList();
            if (!rows.Any(r => r.IsRoot))
                rows.Add(PermissionRow.Root());
            return rows.OrderBy(r => r.IsRoot ? 0 : 1).ThenBy(r => r.Path, StringComparer.Ordinal).ToList();
        }

        private Dictionary<string, FilePermissions> PermissionDictionary()
        {
            var result = new Dictionary<string, FilePermissions>(StringComparer.Ordinal);
            foreach (var row in Permissions)
                result.TryAdd(NormalizedOrRaw(row.Path), row.Permissions);
            return result;
        }

        private Dictionary<string, PathFilter> FilterDictionary()
        {
            var result = new Dictionary<string, PathFilter>(StringComparer.Ordinal);
            foreach (var row in PathFilters)
                result.TryAdd(NormalizedOrRaw(row.Path), row.ToFilter());
            return result;
        }

        /// <summary>A valid path is stored normalized; an invalid one is kept as typed, so the validation can tell about it.</summary>
        private static string NormalizedOrRaw(string path)
        {
            var trimmed = (path ?? "").Trim();
            return trimmed.StartsWith('/') ? VirtualPath.Normalize(trimmed) : trimmed;
        }

        /// <summary>
        /// Writes the form to <paramref name="user"/> (a new user, or the stored copy of an existing one). A new
        /// password is hashed with <see cref="PasswordHasher"/>; the plain text never leaves the form.
        /// </summary>
        /// <remarks>The storage configuration is built and validated by <see cref="StorageConfigService"/>; the caller sets <see cref="User.Storage"/>.</remarks>
        public void ApplyTo(User user, int passwordIterations = PasswordHasher.DefaultIterations)
        {
            if (IsNew)
                user.Username = Username.Trim();
            user.UserRootDirectory = UserRootDirectory.Trim();
            user.VirtualFolders = MountList();
            user.OnlyWhitelistedIps = OnlyWhitelistedIps;
            user.WhitelistedIps = EntryList.Parse(WhitelistedIps);
            user.AllowedAuthMethods = AllowedMethods;
            user.RequireAllOf = RequiredSteps;
            user.DiskQuota = DiskQuota.OrNull(new DiskQuota { MaxSizeBytes = ToBytes(QuotaSizeMiB), MaxFiles = QuotaFiles });
            user.TransferQuota = TransferQuota.OrNull(new TransferQuota
            {
                MaxUploadBytes = ToBytes(UploadQuotaMiB),
                MaxDownloadBytes = ToBytes(DownloadQuotaMiB),
                MaxTotalBytes = ToBytes(TotalQuotaMiB),
            });
            var overrides = BandwidthOverrides
                .Select(o => new BandwidthOverride { Sources = EntryList.Parse(o.Sources), UploadKiBPerSecond = o.UploadKiBPerSecond, DownloadKiBPerSecond = o.DownloadKiBPerSecond })
                .ToList();
            user.Bandwidth = UploadKiBPerSecond <= 0 && DownloadKiBPerSecond <= 0 && overrides.Count == 0
                ? null
                : new BandwidthLimit { UploadKiBPerSecond = UploadKiBPerSecond, DownloadKiBPerSecond = DownloadKiBPerSecond, Overrides = overrides.Count == 0 ? null : overrides };
            user.Permissions = PermissionDictionary();
            var filters = FilterDictionary().Where(f => !f.Value.IsEmpty).ToDictionary(f => f.Key, f => f.Value, StringComparer.Ordinal);
            user.PathFilters = filters.Count == 0 ? null : filters;
            if (!string.IsNullOrEmpty(NewPassword))
                user.HashedPassword = PasswordHasher.Hash(NewPassword, passwordIterations);
            else if (RemovePassword)
                user.HashedPassword = null;
        }

        /// <summary>The mounts of the form, with normalized paths.</summary>
        public List<VirtualFolderMount> MountList() => Mounts
            .Select(m => new VirtualFolderMount
            {
                VirtualFolderId = m.VirtualFolderId,
                MountPath = NormalizedOrRaw(m.MountPath),
                Quota = DiskQuota.OrNull(new DiskQuota { MaxSizeBytes = ToBytes(m.QuotaSizeMiB), MaxFiles = m.QuotaFiles }),
            })
            .ToList();

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (UsesDefaultStorage && string.IsNullOrWhiteSpace(UserRootDirectory))
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

            // Rows that are typed twice are found here; the dictionaries keep only the first of them.
            foreach (var path in Permissions.GroupBy(r => NormalizedOrRaw(r.Path), StringComparer.Ordinal).Where(g => g.Count() > 1 && g.Key.Length > 0))
                yield return new ValidationResult($"The path {path.Key} has permissions twice.", new[] { nameof(Permissions) });
            foreach (var path in PathFilters.GroupBy(r => NormalizedOrRaw(r.Path), StringComparer.Ordinal).Where(g => g.Count() > 1 && g.Key.Length > 0))
                yield return new ValidationResult($"The path {path.Key} has a filter twice.", new[] { nameof(PathFilters) });
            foreach (var problem in PermissionRulesValidator.Validate(PermissionDictionary(), null))
                yield return new ValidationResult(problem, new[] { nameof(Permissions) });
            foreach (var problem in PermissionRulesValidator.Validate(null, FilterDictionary()))
                yield return new ValidationResult(problem, new[] { nameof(PathFilters) });

            if (QuotaSizeMiB < 0 || QuotaFiles < 0 || Mounts.Any(m => m.QuotaSizeMiB < 0 || m.QuotaFiles < 0))
                yield return new ValidationResult("A disk quota cannot be negative (0 is unlimited).", new[] { nameof(QuotaSizeMiB) });
            if (UploadQuotaMiB < 0 || DownloadQuotaMiB < 0 || TotalQuotaMiB < 0)
                yield return new ValidationResult("A transfer quota cannot be negative (0 is unlimited).", new[] { nameof(UploadQuotaMiB) });
            if (UploadKiBPerSecond < 0 || DownloadKiBPerSecond < 0 || BandwidthOverrides.Any(o => o.UploadKiBPerSecond < 0 || o.DownloadKiBPerSecond < 0))
                yield return new ValidationResult("A bandwidth cannot be negative (0 is unlimited).", new[] { nameof(UploadKiBPerSecond) });
            foreach (var row in BandwidthOverrides)
            {
                var sources = EntryList.Parse(row.Sources);
                if (sources.Count == 0)
                    yield return new ValidationResult("Enter the client networks of each bandwidth override.", new[] { nameof(BandwidthOverrides) });
                foreach (var invalid in CidrNotation.FindInvalid(sources))
                    yield return new ValidationResult($"Not a valid network: {invalid}", new[] { nameof(BandwidthOverrides) });
            }
        }
    }

    /// <summary>One virtual folder mounted for a user, in the form.</summary>
    public sealed class MountRow
    {
        public int VirtualFolderId { get; set; }
        public string MountPath { get; set; } = "";

        /// <summary>The disk quota of the folder for this user in MiB (issue #62); 0: unlimited.</summary>
        public decimal QuotaSizeMiB { get; set; }

        /// <summary>The maximum number of files in the folder; 0: unlimited.</summary>
        public long QuotaFiles { get; set; }
    }

    /// <summary>Other bandwidth values for some client networks (issue #62), in the form.</summary>
    public sealed class BandwidthOverrideRow
    {
        /// <summary>The networks in CIDR notation, one per line or separated by commas.</summary>
        public string Sources { get; set; } = "";

        public int UploadKiBPerSecond { get; set; }

        public int DownloadKiBPerSecond { get; set; }
    }
}
