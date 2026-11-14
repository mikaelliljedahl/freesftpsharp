using System.Security.Cryptography;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using SshServer.Interfaces.Users;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>The shared user service (admin UI and <c>ServerConsoleApp user</c>): rules, hashing, keys.</summary>
public sealed class UserAdministrationServiceTests : IDisposable
{
    private readonly TempDirectory _temp = new();
    private readonly InMemorySettingsRepository _repository = new(new ServerSettings());
    private readonly UserAdministrationService _service;

    public UserAdministrationServiceTests() => _service = new UserAdministrationService(_repository);

    public void Dispose() => _temp.Dispose();

    [Fact]
    public void Create_stores_a_user_with_a_pbkdf2_hash_and_the_full_root_path()
    {
        var root = _temp.File("root");

        var user = _service.Create("alice", root, "correct horse", null);

        var stored = _repository.GetUser("alice");
        Assert.NotNull(stored);
        Assert.Equal(root, stored.UserRootDirectory);
        Assert.True(PasswordHasher.IsWellFormed(stored.HashedPassword));
        Assert.True(PasswordHasher.Verify("correct horse", stored.HashedPassword));
        Assert.Null(stored.PublicKeys);
        Assert.Equal("alice", user.Username);
    }

    [Fact]
    public void Create_makes_a_missing_root_directory()
    {
        var root = _temp.File("a/b/c");
        Assert.False(Directory.Exists(root));

        _service.Create("alice", root, "correct horse", null);

        Assert.True(Directory.Exists(root));
    }

    [Fact]
    public void Create_makes_a_relative_root_absolute()
    {
        var user = _service.Create("alice", Path.Combine("relative-root-for-test", ".."), "correct horse", null);
        Assert.True(Path.IsPathRooted(user.UserRootDirectory));
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData("has space")]
    [InlineData("a:b")]
    [InlineData("a/b")]
    [InlineData("a\\b")]
    public void Create_rejects_a_bad_user_name(string name)
    {
        var ex = Assert.Throws<UserAdministrationException>(() => _service.Create(name, _temp.File("r"), "correct horse", null));
        Assert.NotEmpty(ex.Message);
        Assert.Empty(_repository.GetAllUsers());
        Assert.False(Directory.Exists(_temp.File("r")));
    }

    [Fact]
    public void Create_rejects_a_name_over_100_characters()
    {
        Assert.Throws<UserAdministrationException>(() => _service.Create(new string('a', 101), _temp.File("r"), "correct horse", null));
    }

    [Fact]
    public void Create_rejects_a_short_password()
    {
        var ex = Assert.Throws<UserAdministrationException>(() => _service.Create("alice", _temp.File("r"), "short", null));
        Assert.Contains("8", ex.Message);
        Assert.Empty(_repository.GetAllUsers());
    }

    [Fact]
    public void Create_needs_a_password_or_a_key()
    {
        Assert.Throws<UserAdministrationException>(() => _service.Create("alice", _temp.File("r"), null, null));
    }

    [Fact]
    public void Create_rejects_a_duplicate_name_in_any_letter_case()
    {
        _service.Create("Alice", _temp.File("r1"), "correct horse", null);

        var ex = Assert.Throws<UserAdministrationException>(() => _service.Create("alice", _temp.File("r2"), "correct horse", null));

        Assert.Contains("already exists", ex.Message);
        Assert.Single(_repository.GetAllUsers());
        Assert.False(Directory.Exists(_temp.File("r2")));
    }

    [Fact]
    public void TryAdd_refuses_a_duplicate_name_in_any_letter_case()
    {
        Assert.True(_service.TryAdd(new User { Username = "bob", UserRootDirectory = _temp.Path, WhitelistedIps = new List<string>() }));
        Assert.False(_service.TryAdd(new User { Username = "BOB", UserRootDirectory = _temp.Path, WhitelistedIps = new List<string>() }));
        Assert.False(_service.TryAdd(new User { Username = "", UserRootDirectory = _temp.Path, WhitelistedIps = new List<string>() }));
    }

    [Fact]
    public void Remove_deletes_the_user_and_reports_an_unknown_one()
    {
        _service.Create("alice", _temp.File("r"), "correct horse", null);

        Assert.True(_service.Remove("alice"));
        Assert.False(_service.Remove("alice"));
        Assert.Empty(_service.List());
        Assert.True(Directory.Exists(_temp.File("r")), "the root directory must stay");
    }

    [Fact]
    public void An_OpenSsh_rsa_public_key_is_stored_as_an_entry_of_the_same_key()
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);

        var user = _service.Create("keyuser", _temp.File("r"), null, ToOpenSshLine(parameters, "me@laptop"));

        Assert.Null(user.HashedPassword);
        var entry = Assert.Single(_repository.GetUser("keyuser").PublicKeys!);
        Assert.Equal("ssh-rsa", entry.KeyType);
        Assert.Equal(Convert.ToBase64String(SshPublicKey.RsaBlob(parameters)), entry.KeyBase64);
        Assert.Equal("me@laptop", entry.Comment);
        Assert.Equal(PublicKeySource.Admin, entry.Source);
    }

    [Fact]
    public void A_pem_public_key_is_accepted()
    {
        using var rsa = RSA.Create(2048);

        _service.Create("pemuser", _temp.File("r"), null, rsa.ExportSubjectPublicKeyInfoPem());

        Assert.Single(_repository.GetUser("pemuser").PublicKeys!);
    }

    [Fact]
    public void An_authorized_keys_file_with_ed25519_ecdsa_and_rsa_keys_gives_one_entry_per_key()
    {
        var text = string.Join("\n", "# keys", TestUserKeys.Ed25519().AuthorizedKeysLine, TestUserKeys.EcdsaNistP256().AuthorizedKeysLine,
            TestUserKeys.Rsa().AuthorizedKeysLine);

        _service.Create("multi", _temp.File("r"), null, text);

        Assert.Equal(new[] { "ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa" }, _repository.GetUser("multi").PublicKeys!.Select(k => k.KeyType));
    }

    [Theory]
    [InlineData("not a key")]
    [InlineData("ssh-dss AAAAB3NzaC1kc3M= old")]
    [InlineData("ssh-rsa !!!notbase64")]
    [InlineData("ssh-rsa AAAA")]
    [InlineData("from=\"10.0.0.0/8\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me")]
    public void A_bad_public_key_is_rejected(string key)
    {
        Assert.Throws<UserAdministrationException>(() => _service.Create("keyuser", _temp.File("r"), null, key));
        Assert.Empty(_repository.GetAllUsers());
    }

    [Fact]
    public void Keys_are_added_with_an_expiry_and_a_key_the_user_has_is_skipped()
    {
        var first = TestUserKeys.Ed25519();
        _service.Create("bob", _temp.File("r"), null, first.AuthorizedKeysLine);
        var expires = new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        var (added, skipped) = _service.AddPublicKeys("bob", first.AuthorizedKeysLine + "\n" + TestUserKeys.Rsa().AuthorizedKeysLine, expires);

        Assert.Equal((1, 1), (added, skipped));
        var keys = _repository.GetUser("bob").PublicKeys!;
        Assert.Equal(2, keys.Count);
        Assert.Null(keys[0].ExpiresAt);
        Assert.Equal(expires, keys[1].ExpiresAt);
    }

    [Fact]
    public void Nothing_is_added_when_one_line_is_refused()
    {
        _service.Create("bob", _temp.File("r"), "correct horse", null);

        var ex = Assert.Throws<UserAdministrationException>(() =>
            _service.AddPublicKeys("bob", TestUserKeys.Ed25519().AuthorizedKeysLine + "\nrestrict " + TestUserKeys.Ed25519().AuthorizedKeysLine, null));

        Assert.Contains("Line 2", ex.Message);
        Assert.Null(_repository.GetUser("bob").PublicKeys);
    }

    [Fact]
    public void A_key_is_removed_by_its_blob_and_an_unknown_key_or_user_is_reported()
    {
        var keep = TestUserKeys.Ed25519();
        var remove = TestUserKeys.Ed25519();
        _service.Create("bob", _temp.File("r"), null, keep.AuthorizedKeysLine + "\n" + remove.AuthorizedKeysLine);

        Assert.True(_service.RemovePublicKey("bob", remove.Entry.KeyBase64));
        Assert.False(_service.RemovePublicKey("bob", remove.Entry.KeyBase64));

        Assert.Equal(keep.Entry.KeyBase64, Assert.Single(_repository.GetUser("bob").PublicKeys!).KeyBase64);
        Assert.Throws<UserAdministrationException>(() => _service.RemovePublicKey("nobody", keep.Entry.KeyBase64));
    }

    [Fact]
    public void A_generated_key_entry_is_added_once()
    {
        _service.Create("bob", _temp.File("r"), "correct horse", null);
        var key = TestUserKeys.Ed25519();

        Assert.True(_service.AddPublicKey("bob", key.Entry));
        Assert.False(_service.AddPublicKey("bob", key.Entry));

        Assert.Single(_repository.GetUser("bob").PublicKeys!);
    }

    internal static string ToOpenSshLine(RSAParameters p, string comment)
    {
        static byte[] Str(byte[] data) => [.. BitConverter.GetBytes(data.Length).Reverse(), .. data];
        static byte[] Mpint(byte[] data) => Str(data[0] >= 0x80 ? [0, .. data] : data);
        var blob = new byte[] { }.Concat(Str("ssh-rsa"u8.ToArray())).Concat(Mpint(p.Exponent!)).Concat(Mpint(p.Modulus!)).ToArray();
        return "ssh-rsa " + Convert.ToBase64String(blob) + " " + comment;
    }
}
