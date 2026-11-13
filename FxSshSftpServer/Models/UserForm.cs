using SshServer.Interfaces;
using SshServer.Interfaces.Security;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace FxSshSftpServer.Models
{
    /// <summary>The add/edit form of an SFTP user.</summary>
    public sealed class UserForm : IValidatableObject
    {
        public const int MinimumPasswordLength = 8;

        /// <summary>True for a user that is not saved yet. The user name of a saved user cannot change (the repository finds users by name).</summary>
        public bool IsNew { get; set; }

        [Required(ErrorMessage = "Enter a user name.")]
        [StringLength(100, ErrorMessage = "The user name can have at most 100 characters.")]
        [RegularExpression(@"^[^\s:/\\]+$", ErrorMessage = "The user name cannot have spaces, ':', '/' or '\\'.")]
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
        };

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
        }
    }
}
