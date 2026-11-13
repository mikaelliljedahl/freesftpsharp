namespace FxSshSftpServer.Security
{
    /// <summary>
    /// The single local admin account of the web UI (configuration section "AdminAuth").
    /// It is separate from the SFTP users in the settings repository.
    /// </summary>
    public sealed class AdminAuthOptions
    {
        public const string SectionName = "AdminAuth";

        public string UserName { get; set; }

        /// <summary>A hash made by <see cref="AdminPasswordHasher.Hash"/>; never a plaintext password.</summary>
        public string PasswordHash { get; set; }

        /// <summary>Failed logins from one client before it is locked out.</summary>
        public int MaxFailedLogins { get; set; } = 5;

        public int LockoutMinutes { get; set; } = 15;

        public bool IsConfigured =>
            !string.IsNullOrWhiteSpace(UserName) && AdminPasswordHasher.IsWellFormed(PasswordHash);
    }
}
