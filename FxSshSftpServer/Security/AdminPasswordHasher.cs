using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace FxSshSftpServer.Security
{
    /// <summary>
    /// Salted PBKDF2-SHA256 hashes for the admin UI password.
    /// Format: <c>PBKDF2-SHA256.&lt;iterations&gt;.&lt;base64 salt&gt;.&lt;base64 key&gt;</c>.
    /// The '.' separator needs no escaping in JSON, environment variables or shells.
    /// </summary>
    public static class AdminPasswordHasher
    {
        public const string Algorithm = "PBKDF2-SHA256";
        public const int DefaultIterations = 600_000;
        public const int MinimumIterations = 100_000;

        // Upper bound so a broken config value cannot make every login burn CPU for minutes.
        public const int MaximumIterations = 10_000_000;

        private const int SaltSize = 16;
        private const int KeySize = 32;

        public static string Hash(string password, int iterations = DefaultIterations)
        {
            ArgumentNullException.ThrowIfNull(password);
            if (iterations < MinimumIterations || iterations > MaximumIterations)
                throw new ArgumentOutOfRangeException(nameof(iterations), iterations,
                    $"Iterations must be between {MinimumIterations} and {MaximumIterations}.");

            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            var key = Derive(password, salt, iterations);
            return string.Join('.', Algorithm, iterations.ToString(CultureInfo.InvariantCulture),
                Convert.ToBase64String(salt), Convert.ToBase64String(key));
        }

        public static bool IsWellFormed(string encodedHash) => TryParse(encodedHash, out _, out _, out _);

        public static bool Verify(string password, string encodedHash)
        {
            if (password is null || !TryParse(encodedHash, out var iterations, out var salt, out var expected))
                return false;

            var actual = Derive(password, salt, iterations);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }

        /// <summary>
        /// Runs the same key derivation as a real check, so a request for an unknown user name takes as long as
        /// one for the real user.
        /// </summary>
        internal static void BurnEquivalentWork(string encodedHash)
        {
            var iterations = TryParse(encodedHash, out var configured, out _, out _) ? configured : DefaultIterations;
            Derive("dummy", new byte[SaltSize], iterations);
        }

        private static byte[] Derive(string password, byte[] salt, int iterations) =>
            Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, KeySize);

        private static bool TryParse(string encodedHash, out int iterations, out byte[] salt, out byte[] key)
        {
            iterations = 0;
            salt = null;
            key = null;
            if (string.IsNullOrWhiteSpace(encodedHash))
                return false;

            var parts = encodedHash.Trim().Split('.');
            if (parts.Length != 4 || !string.Equals(parts[0], Algorithm, StringComparison.Ordinal))
                return false;
            if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out iterations)
                || iterations < MinimumIterations || iterations > MaximumIterations)
                return false;

            try
            {
                salt = Convert.FromBase64String(parts[2]);
                key = Convert.FromBase64String(parts[3]);
            }
            catch (FormatException)
            {
                return false;
            }

            return salt.Length >= SaltSize && key.Length == KeySize;
        }
    }
}
