using FreeSftpSharp.Tests.Infrastructure;
using FxSsh.SshServerModule;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>
/// <c>UserLogics.VerifyUserPassword</c>: PBKDF2 hashes, the old unsalted SHA-256 hashes and their migration (issue #23).
/// </summary>
public sealed class UserPasswordVerificationTests
{
    private const string Password = "s3cret pw";

    private readonly InMemorySettingsRepository _repository = new(new ServerSettings());
    private readonly CapturingLogger _logger = new();

    private User AddUser(string hashedPassword, string username = "alice")
    {
        _repository.AddUser(new User { Username = username, HashedPassword = hashedPassword, WhitelistedIps = new List<string>() });
        return _repository.GetUser(username);
    }

    private bool Verify(User user, string password) => UserLogics.VerifyUserPassword(user, password, _repository, _logger);

    [Fact]
    public void A_pbkdf2_hash_accepts_the_correct_password_and_is_not_rewritten()
    {
        var hash = TestCredentials.HashPassword(Password);
        var user = AddUser(hash);

        Assert.True(Verify(user, Password));
        Assert.Equal(hash, _repository.GetUser("alice").HashedPassword);
    }

    [Fact]
    public void A_pbkdf2_hash_rejects_a_wrong_password()
    {
        var hash = TestCredentials.HashPassword(Password);
        var user = AddUser(hash);

        Assert.False(Verify(user, "s3cret pW"));
        Assert.False(Verify(user, ""));
        Assert.Equal(hash, _repository.GetUser("alice").HashedPassword);
    }

    [Theory]
    [InlineData(2)] // salt
    [InlineData(3)] // derived key
    public void A_tampered_pbkdf2_hash_rejects_the_correct_password(int partIndex)
    {
        var parts = TestCredentials.HashPassword(Password).Split('.');
        var bytes = Convert.FromBase64String(parts[partIndex]);
        bytes[^1] ^= 0x80;
        parts[partIndex] = Convert.ToBase64String(bytes);
        var user = AddUser(string.Join('.', parts));

        Assert.False(Verify(user, Password));
    }

    [Fact]
    public void A_legacy_hash_accepts_the_correct_password_once_and_is_upgraded_to_pbkdf2()
    {
        var legacy = TestCredentials.LegacySha256Hash(Password);
        var user = AddUser(legacy);

        Assert.True(Verify(user, Password));

        var stored = _repository.GetUser("alice").HashedPassword;
        Assert.NotEqual(legacy, stored);
        Assert.False(PasswordHasher.IsLegacySha256(stored));
        Assert.True(PasswordHasher.IsWellFormed(stored));
        Assert.StartsWith($"{PasswordHasher.Algorithm}.{PasswordHasher.DefaultIterations}.", stored);
        Assert.True(PasswordHasher.Verify(Password, stored));

        // The next login uses the new hash.
        Assert.True(Verify(_repository.GetUser("alice"), Password));
        Assert.Equal(stored, _repository.GetUser("alice").HashedPassword);
    }

    [Fact]
    public void The_migration_is_logged_at_information_without_the_password()
    {
        var user = AddUser(TestCredentials.LegacySha256Hash(Password));

        Assert.True(Verify(user, Password));

        var entry = Assert.Single(_logger.Entries);
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Contains("alice", entry.Message);
        Assert.DoesNotContain(Password, entry.Message);
    }

    [Fact]
    public void A_legacy_hash_rejects_a_wrong_password_and_is_not_upgraded()
    {
        var legacy = TestCredentials.LegacySha256Hash(Password);
        var user = AddUser(legacy);

        Assert.False(Verify(user, "wrong"));
        Assert.Equal(legacy, _repository.GetUser("alice").HashedPassword);
        Assert.Empty(_logger.Entries);
    }

    [Fact]
    public void A_tampered_legacy_hash_rejects_the_correct_password()
    {
        var bytes = Convert.FromBase64String(TestCredentials.LegacySha256Hash(Password));
        bytes[0] ^= 0x01;
        var user = AddUser(Convert.ToBase64String(bytes));

        Assert.False(Verify(user, Password));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("s3cret pw")] // a plaintext value is not a hash
    [InlineData("AAAA")] // base64, but not 32 bytes
    public void A_user_without_a_valid_hash_is_rejected(string? stored)
    {
        var user = AddUser(stored!);

        Assert.False(Verify(user, Password));
        Assert.Equal(stored, _repository.GetUser("alice").HashedPassword);
    }

    [Fact]
    public void A_null_password_is_rejected()
    {
        var user = AddUser(TestCredentials.HashPassword(Password));

        Assert.False(Verify(user, null!));
    }

    [Fact]
    public void Legacy_format_is_detected_only_for_base64_of_32_bytes()
    {
        Assert.True(PasswordHasher.IsLegacySha256(TestCredentials.LegacySha256Hash("x")));
        Assert.False(PasswordHasher.IsLegacySha256(TestCredentials.HashPassword("x")));
        Assert.False(PasswordHasher.IsLegacySha256(null));
        Assert.False(PasswordHasher.IsLegacySha256(Convert.ToBase64String(new byte[31])));
        Assert.True(PasswordHasher.VerifyLegacySha256("1234", "A6xnQhbz4Vx2HuGl4lXwZ5U2I8iziLRFnhP5eNfIRvQ="));
        Assert.False(PasswordHasher.VerifyLegacySha256("12345", "A6xnQhbz4Vx2HuGl4lXwZ5U2I8iziLRFnhP5eNfIRvQ="));
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add((logLevel, formatter(state, exception)));
        }
    }
}
