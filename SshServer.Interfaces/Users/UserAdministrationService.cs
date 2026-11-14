using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using SshServer.Interfaces.Authentication;
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
        /// <param name="publicKeyText">
        /// The content of an OpenSSH <c>.pub</c> or <c>authorized_keys</c> file (ed25519, ECDSA or RSA keys, one per line)
        /// or a PEM public key.
        /// </param>
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

            var publicKeys = publicKeyText == null ? null : ParsePublicKeys(publicKeyText, PublicKeySource.Admin, null);

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
                PublicKeys = publicKeys?.ToList(),
                OnlyWhitelistedIps = false,
                WhitelistedIps = new List<string>(),
            };
            if (!TryAdd(user))
                throw new UserAdministrationException($"The user '{name}' could not be created.");
            return user;
        }

        /// <summary>
        /// Adds the keys of an <c>authorized_keys</c> text (or one PEM public key) to a user. A key that the user already
        /// has is skipped. Nothing is added when a line is not a supported key: the exception tells which lines.
        /// </summary>
        /// <param name="expiresAtUtc">The expiry of the new keys, or null.</param>
        /// <returns>The number of added keys and of skipped keys (already in the list).</returns>
        public (int Added, int Skipped) AddPublicKeys(string username, string text, DateTime? expiresAtUtc,
            PublicKeySource source = PublicKeySource.Admin)
        {
            var user = GetExistingUser(username);
            var keys = ParsePublicKeys(text, source, expiresAtUtc);
            var list = user.PublicKeys?.ToList() ?? new List<PublicKeyEntry>();
            var added = 0;
            foreach (var key in keys)
            {
                if (list.Any(k => k.KeyBase64 == key.KeyBase64))
                    continue;
                list.Add(key);
                added++;
            }
            if (added > 0)
                Save(user, list);
            return (added, keys.Count - added);
        }

        /// <summary>Adds one key entry (for example a generated key). Returns false when the user already has the key.</summary>
        public bool AddPublicKey(string username, PublicKeyEntry key)
        {
            ArgumentNullException.ThrowIfNull(key);
            var user = GetExistingUser(username);
            var list = user.PublicKeys?.ToList() ?? new List<PublicKeyEntry>();
            if (list.Any(k => k.KeyBase64 == key.KeyBase64))
                return false;
            list.Add(key);
            Save(user, list);
            return true;
        }

        /// <summary>Removes the key with this blob (base64) from a user. Returns false when the user does not have it.</summary>
        public bool RemovePublicKey(string username, string keyBase64)
        {
            var user = GetExistingUser(username);
            var list = user.PublicKeys?.ToList() ?? new List<PublicKeyEntry>();
            if (list.RemoveAll(k => k.KeyBase64 == keyBase64) == 0)
                return false;
            Save(user, list);
            return true;
        }

        /// <summary>
        /// Reads the keys of a text. Throws <see cref="UserAdministrationException"/> with all refused lines, or when
        /// there is no key.
        /// </summary>
        public static IReadOnlyList<PublicKeyEntry> ParsePublicKeys(string text, PublicKeySource source, DateTime? expiresAtUtc)
        {
            var result = SshPublicKey.ParseAuthorizedKeys(text ?? string.Empty, source, DateTime.UtcNow);
            if (result.Errors.Count > 0)
                throw new UserAdministrationException(string.Join(Environment.NewLine, result.Errors));
            if (result.Keys.Count == 0)
                throw new UserAdministrationException("There is no public key in the text.");
            foreach (var key in result.Keys)
                key.ExpiresAt = expiresAtUtc;
            return result.Keys;
        }

        private User GetExistingUser(string username) =>
            _repository.GetUser(username) ?? throw new UserAdministrationException($"The user '{username}' does not exist.");

        private void Save(User user, List<PublicKeyEntry> keys)
        {
            user.PublicKeys = keys;
            if (!_repository.UpdateUser(user))
                throw new UserAdministrationException($"The keys of '{user.Username}' could not be saved.");
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
