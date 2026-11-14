using SshServer.Interfaces.Users;
using SshServer.Interfaces;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using System.Linq;
using SshServer.Interfaces.Security;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

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

        [Required(ErrorMessage = "Enter the root directory of the user on the server.")]
        public string UserRootDirectory { get; set; } = "";

        /// <summary>A new password. Empty: keep the stored password.</summary>
        public string NewPassword { get; set; } = "";

        public string ConfirmPassword { get; set; } = "";

        /// <summary>Removes the stored password (for a user that logs in with a key only).</summary>
        public bool RemovePassword { get; set; }

        public bool OnlyWhitelistedIps { get; set; }

        [CidrList]
        public string WhitelistedIps { get; set; } = "";

        public bool HasPassword { get; set; }

        public string RsaPublicKey { get; set; }

        public DateTime LastSuccessfulLogin { get; set; }

        /// <summary>The permissions per directory (issue #59); the first row is always "/".</summary>
        public List<PermissionRow> Permissions { get; set; } = new() { PermissionRow.Root() };

        /// <summary>The path filters per directory (issue #59).</summary>
        public List<PathFilterRow> PathFilters { get; set; } = new();

        public static UserForm New() => new() { IsNew = true };

        public static UserForm From(User user) => new()
        {
            IsNew = false,
            Username = user.Username ?? "",
            UserRootDirectory = user.UserRootDirectory ?? "",
            OnlyWhitelistedIps = user.OnlyWhitelistedIps,
            WhitelistedIps = EntryList.Format(user.WhitelistedIps),
            HasPassword = !string.IsNullOrWhiteSpace(user.HashedPassword),
            RsaPublicKey = user.RsaPublicKey,
            LastSuccessfulLogin = user.LastSuccessfulLogin,
            Permissions = PermissionRowsOf(user.Permissions),
            PathFilters = (user.PathFilters ?? new Dictionary<string, PathFilter>())
                .OrderBy(f => f.Key, StringComparer.Ordinal)
                .Select(f => PathFilterRow.From(f.Key, f.Value))
                .ToList(),
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
        public void ApplyTo(User user, int passwordIterations = PasswordHasher.DefaultIterations)
        {
            if (IsNew)
                user.Username = Username.Trim();
            user.UserRootDirectory = UserRootDirectory.Trim();
            user.OnlyWhitelistedIps = OnlyWhitelistedIps;
            user.WhitelistedIps = EntryList.Parse(WhitelistedIps);
            user.Permissions = PermissionDictionary();
            var filters = FilterDictionary().Where(f => !f.Value.IsEmpty).ToDictionary(f => f.Key, f => f.Value, StringComparer.Ordinal);
            user.PathFilters = filters.Count == 0 ? null : filters;
            if (!string.IsNullOrEmpty(NewPassword))
                user.HashedPassword = PasswordHasher.Hash(NewPassword, passwordIterations);
            else if (RemovePassword)
                user.HashedPassword = null;
        }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (!string.IsNullOrEmpty(NewPassword))
            {
                if (NewPassword.Length < MinimumPasswordLength)
                    yield return new ValidationResult($"The password must have at least {MinimumPasswordLength} characters.", new[] { nameof(NewPassword) });
                if (!string.Equals(NewPassword, ConfirmPassword, StringComparison.Ordinal))
                    yield return new ValidationResult("The passwords are not the same.", new[] { nameof(ConfirmPassword) });
            }

            // Rows that are typed twice are found here; the dictionaries keep only the first of them.
            foreach (var path in Permissions.GroupBy(r => NormalizedOrRaw(r.Path), StringComparer.Ordinal).Where(g => g.Count() > 1 && g.Key.Length > 0))
                yield return new ValidationResult($"The path {path.Key} has permissions twice.", new[] { nameof(Permissions) });
            foreach (var path in PathFilters.GroupBy(r => NormalizedOrRaw(r.Path), StringComparer.Ordinal).Where(g => g.Count() > 1 && g.Key.Length > 0))
                yield return new ValidationResult($"The path {path.Key} has a filter twice.", new[] { nameof(PathFilters) });
            foreach (var problem in PermissionRulesValidator.Validate(PermissionDictionary(), null))
                yield return new ValidationResult(problem, new[] { nameof(Permissions) });
            foreach (var problem in PermissionRulesValidator.Validate(null, FilterDictionary()))
                yield return new ValidationResult(problem, new[] { nameof(PathFilters) });
        }
    }
}
