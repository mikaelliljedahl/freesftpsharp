using System.Security.Cryptography;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using SshServer.Interfaces.Users;
using SshServer.Interfaces;
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
        Assert.Null(stored.RsaPublicKey);
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
    public void An_OpenSsh_public_key_is_stored_as_the_csp_blob_of_the_same_key()
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);

        var user = _service.Create("keyuser", _temp.File("r"), null, ToOpenSshLine(parameters, "me@laptop"));

        Assert.Null(user.HashedPassword);
        using var csp = new RSACryptoServiceProvider();
        var storedKey = _repository.GetUser("keyuser").RsaPublicKey;
        Assert.NotNull(storedKey);
        csp.ImportCspBlob(Convert.FromBase64String(storedKey));
        var imported = csp.ExportParameters(false);
        Assert.Equal(parameters.Modulus, imported.Modulus);
        Assert.Equal(parameters.Exponent, imported.Exponent);
    }

    [Fact]
    public void A_pem_public_key_is_accepted()
    {
        using var rsa = RSA.Create(2048);

        _service.Create("pemuser", _temp.File("r"), null, rsa.ExportSubjectPublicKeyInfoPem());

        Assert.False(string.IsNullOrEmpty(_repository.GetUser("pemuser").RsaPublicKey));
    }

    [Theory]
    [InlineData("not a key")]
    [InlineData("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me")]
    [InlineData("ssh-rsa !!!notbase64")]
    [InlineData("ssh-rsa AAAA")]
    public void A_bad_public_key_is_rejected(string key)
    {
        Assert.Throws<UserAdministrationException>(() => _service.Create("keyuser", _temp.File("r"), null, key));
        Assert.Empty(_repository.GetAllUsers());
    }

    internal static string ToOpenSshLine(RSAParameters p, string comment)
    {
        static byte[] Str(byte[] data) => [.. BitConverter.GetBytes(data.Length).Reverse(), .. data];
        static byte[] Mpint(byte[] data) => Str(data[0] >= 0x80 ? [0, .. data] : data);
        var blob = new byte[] { }.Concat(Str("ssh-rsa"u8.ToArray())).Concat(Mpint(p.Exponent!)).Concat(Mpint(p.Modulus!)).ToArray();
        return "ssh-rsa " + Convert.ToBase64String(blob) + " " + comment;
    }
}
