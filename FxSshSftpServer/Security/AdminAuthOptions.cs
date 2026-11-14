using SshServer.Interfaces.Security;

namespace FxSshSftpServer.Security
{
    /// <summary>
    /// The configuration section "AdminAuth": the login throttle, and the bootstrap admin account. When the settings
    /// database has no administrator yet, <see cref="UserName"/> and <see cref="PasswordHash"/> are imported once as the
    /// first super admin (see <see cref="AdminAuthenticationSetup.UseAdminUiRequiresCredential"/>); after that the
    /// stored administrators are used and these two values are not read again.
    /// </summary>
    public sealed class AdminAuthOptions
    {
        public const string SectionName = "AdminAuth";

        public string UserName { get; set; }

        /// <summary>A hash made by <see cref="PasswordHasher.Hash"/>; never a plaintext password.</summary>
        public string PasswordHash { get; set; }

        /// <summary>Failed logins from one client before it is locked out.</summary>
        public int MaxFailedLogins { get; set; } = 5;

        public int LockoutMinutes { get; set; } = 15;

        public bool IsConfigured =>
            !string.IsNullOrWhiteSpace(UserName) && PasswordHasher.IsWellFormed(PasswordHash);
    }
}
