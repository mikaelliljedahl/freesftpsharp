using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using SshServer.Interfaces.Security;

namespace SshServer.Interfaces.Users
{
    /// <summary>
    /// The one application service for SFTP users. The admin UI (Users page) and the command line
    /// (<c>ServerConsoleApp user ...</c>) both use it, so the rules (user name, minimum password length, duplicate
    /// names, password hash, key format) exist in one place.
    /// </summary>
    public sealed class UserAdministrationService
    {
        public const int MinimumPasswordLength = 8;
        public const int MaximumUserNameLength = 100;

        /// <summary>The user name: no spaces, ':', '/' or '\'.</summary>
        public const string UserNamePattern = @"^[^\s:/\\]+$";

        private readonly ISettingsRepository _repository;

        public UserAdministrationService(ISettingsRepository repository)
        {
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        }

        public IReadOnlyList<User> List() => _repository.GetAllUsers();

        /// <summary>
        /// Adds a user. Returns false when the name is empty or already used (case-insensitive) or the repository
        /// refuses it. The name rules are checked by the caller (<see cref="ValidateUserName"/>).
        /// </summary>
        public bool TryAdd(User user)
        {
            var name = user.Username?.Trim();
            if (string.IsNullOrEmpty(name))
                return false;
            if (_repository.GetAllUsers().Any(u => string.Equals(u.Username, name, StringComparison.OrdinalIgnoreCase)))
                return false;
            return _repository.AddUser(user);
        }

        /// <summary>Removes a user. Returns false when there is no such user. The files in the root directory stay.</summary>
        public bool Remove(string username) => _repository.RemoveUser(username);

        /// <summary>Returns an error text, or null when the name is valid.</summary>
        public static string? ValidateUserName(string? username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return "Enter a user name.";
            if (username.Length > MaximumUserNameLength)
                return $"The user name can have at most {MaximumUserNameLength} characters.";
            if (!System.Text.RegularExpressions.Regex.IsMatch(username, UserNamePattern))
                return "The user name cannot have spaces, ':', '/' or '\\'.";
            return null;
        }

        /// <summary>Returns an error text, or null when the password is acceptable.</summary>
        public static string? ValidatePassword(string? password) =>
            string.IsNullOrEmpty(password) || password.Length < MinimumPasswordLength
                ? $"The password must have at least {MinimumPasswordLength} characters."
                : null;

        /// <summary>
        /// Creates a user from plain input (the command line). The password is hashed here; the plain text is not
        /// kept. A missing root directory is created. Throws <see cref="UserAdministrationException"/> with a message
        /// for the operator when the input is not valid.
        /// </summary>
        /// <param name="publicKeyText">The content of an OpenSSH <c>.pub</c> file or a PEM public key (RSA).</param>
        public User Create(string? username, string? rootDirectory, string? password, string? publicKeyText)
        {
            var name = username?.Trim() ?? string.Empty;
            var nameError = ValidateUserName(name);
            if (nameError != null)
                throw new UserAdministrationException(nameError);
            if (string.IsNullOrWhiteSpace(rootDirectory))
                throw new UserAdministrationException("Enter the root directory of the user.");
            if (password == null && publicKeyText == null)
                throw new UserAdministrationException("The user needs a password or a public key.");
            if (password != null)
            {
                var passwordError = ValidatePassword(password);
                if (passwordError != null)
                    throw new UserAdministrationException(passwordError);
            }

            var publicKey = publicKeyText == null ? null : ConvertPublicKey(publicKeyText);

            if (_repository.GetAllUsers().Any(u => string.Equals(u.Username, name, StringComparison.OrdinalIgnoreCase)))
                throw new UserAdministrationException($"The user '{name}' already exists.");

            string root;
            try
            {
                root = Path.GetFullPath(rootDirectory.Trim());
                Directory.CreateDirectory(root);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                throw new UserAdministrationException($"The root directory '{rootDirectory}' cannot be created: {ex.Message}");
            }

            var user = new User
            {
                Username = name,
                UserRootDirectory = root,
                HashedPassword = password == null ? null : PasswordHasher.Hash(password),
                RsaPublicKey = publicKey,
                OnlyWhitelistedIps = false,
                WhitelistedIps = new List<string>(),
            };
            if (!TryAdd(user))
                throw new UserAdministrationException($"The user '{name}' could not be created.");
            return user;
        }

        /// <summary>
        /// Converts an RSA public key (OpenSSH <c>ssh-rsa AAAA...</c> line or a PEM) to the stored format: a base64
        /// CSP blob, the same as the admin UI makes.
        /// </summary>
        public static string ConvertPublicKey(string text)
        {
            try
            {
                var trimmed = text.Trim();
                RSAParameters parameters;
                if (trimmed.StartsWith("-----BEGIN", StringComparison.Ordinal))
                {
                    using var pem = RSA.Create();
                    pem.ImportFromPem(trimmed);
                    parameters = pem.ExportParameters(false);
                }
                else
                {
                    parameters = ParseOpenSshRsaKey(trimmed);
                }

                using var csp = new RSACryptoServiceProvider();
                csp.ImportParameters(parameters);
                return Convert.ToBase64String(csp.ExportCspBlob(false));
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException or InvalidOperationException)
            {
                throw new UserAdministrationException("The public key is not a valid RSA public key (OpenSSH 'ssh-rsa' line or PEM). Only RSA keys are supported.");
            }
        }

        private static RSAParameters ParseOpenSshRsaKey(string line)
        {
            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || parts[0] != "ssh-rsa")
                throw new FormatException("Not an ssh-rsa key.");
            var blob = Convert.FromBase64String(parts[1]);
            var position = 0;
            if (Encoding.ASCII.GetString(ReadString(blob, ref position)) != "ssh-rsa")
                throw new FormatException("Not an ssh-rsa key.");
            var exponent = ReadString(blob, ref position);
            var modulus = ReadString(blob, ref position);
            return new RSAParameters
            {
                Exponent = TrimLeadingZeros(exponent),
                Modulus = TrimLeadingZeros(modulus),
            };
        }

        private static byte[] ReadString(byte[] data, ref int position)
        {
            if (position + 4 > data.Length)
                throw new FormatException("Truncated key.");
            var length = (data[position] << 24) | (data[position + 1] << 16) | (data[position + 2] << 8) | data[position + 3];
            position += 4;
            if (length < 0 || position + length > data.Length)
                throw new FormatException("Truncated key.");
            var result = new byte[length];
            Array.Copy(data, position, result, 0, length);
            position += length;
            return result;
        }

        private static byte[] TrimLeadingZeros(byte[] value)
        {
            var skip = 0;
            while (skip < value.Length - 1 && value[skip] == 0)
                skip++;
            return value.Skip(skip).ToArray();
        }
    }

    /// <summary>Invalid input for a user operation. The message is meant for the operator.</summary>
    public sealed class UserAdministrationException : Exception
    {
        public UserAdministrationException(string message) : base(message)
        {
        }
    }
}
