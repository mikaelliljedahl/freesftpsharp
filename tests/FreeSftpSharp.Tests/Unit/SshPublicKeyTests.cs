using System.Security.Cryptography;
using System.Text;
using FreeSftpSharp.Tests.Infrastructure;
using FxSsh;
using FxSsh.Algorithms;
using SshServer.Interfaces.Authentication;

namespace FreeSftpSharp.Tests.Unit;

/// <summary><see cref="SshPublicKey"/>: authorized_keys lines, PEM keys, the old CSP blob, fingerprints and what is refused (issue #58).</summary>
public sealed class SshPublicKeyTests
{
    private static readonly DateTime Now = new(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);

    private static PublicKeyEntry Parse(string text) => SshPublicKey.Parse(text, PublicKeySource.Admin, Now);

    [Fact]
    public void An_ed25519_line_gives_the_type_blob_comment_and_fingerprint()
    {
        var key = TestUserKeys.Ed25519();
        var line = "ssh-ed25519 " + key.Entry.KeyBase64 + " alice@laptop  work";

        var entry = Parse(line);

        Assert.Equal("ssh-ed25519", entry.KeyType);
        Assert.Equal(key.Entry.KeyBase64, entry.KeyBase64);
        Assert.Equal("alice@laptop  work", entry.Comment);
        Assert.Equal(Now, entry.AddedAt);
        Assert.Null(entry.ExpiresAt);
        Assert.Equal(PublicKeySource.Admin, entry.Source);
        Assert.Equal("SHA256:" + Convert.ToBase64String(SHA256.HashData(key.Blob)).TrimEnd('='), entry.Fingerprint);
    }

    [Fact]
    public void The_fingerprint_is_the_one_that_FxSsh_computes_for_the_login_request()
    {
        var pem = KeyGenerator.GenerateECDsaKeyPem("nistp256");
        var algorithm = new EcdsaKey("nistp256", pem);
        var blob = algorithm.CreateKeyAndCertificatesData();

        var entry = SshPublicKey.FromBlob(blob, null, PublicKeySource.Admin, Now);

        Assert.Equal("ecdsa-sha2-nistp256", entry.KeyType);
        Assert.Equal("SHA256:" + algorithm.GetFingerprint().TrimEnd('='), entry.Fingerprint);
    }

    [Fact]
    public void Rsa_and_ecdsa_lines_are_read()
    {
        var rsa = TestUserKeys.Rsa();
        var ecdsa = TestUserKeys.EcdsaNistP256();

        Assert.Equal("ssh-rsa", Parse(rsa.AuthorizedKeysLine).KeyType);
        Assert.Equal(rsa.Entry.KeyBase64, Parse(rsa.AuthorizedKeysLine).KeyBase64);
        Assert.Equal("ecdsa-sha2-nistp256", Parse(ecdsa.AuthorizedKeysLine).KeyType);
    }

    [Fact]
    public void Pem_public_keys_of_rsa_and_ecdsa_are_read()
    {
        using var rsa = RSA.Create(2048);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        var rsaEntry = Parse(rsa.ExportSubjectPublicKeyInfoPem());
        var ecdsaEntry = Parse(ecdsa.ExportSubjectPublicKeyInfoPem());

        Assert.Equal(Convert.ToBase64String(SshPublicKey.RsaBlob(rsa.ExportParameters(false))), rsaEntry.KeyBase64);
        Assert.Equal("ecdsa-sha2-nistp384", ecdsaEntry.KeyType);
    }

    [Fact]
    public void An_authorized_keys_file_gives_one_entry_per_key_and_skips_comments_and_empty_lines()
    {
        var text = string.Join("\r\n",
            "# my keys",
            TestUserKeys.Ed25519().AuthorizedKeysLine,
            "",
            "   ",
            TestUserKeys.Rsa().AuthorizedKeysLine,
            TestUserKeys.EcdsaNistP256().AuthorizedKeysLine);

        var result = SshPublicKey.ParseAuthorizedKeys(text, PublicKeySource.SelfService, Now);

        Assert.Empty(result.Errors);
        Assert.Equal(new[] { "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256" }, result.Keys.Select(k => k.KeyType));
        Assert.All(result.Keys, k => Assert.Equal(PublicKeySource.SelfService, k.Source));
    }

    [Fact]
    public void The_errors_of_an_authorized_keys_file_name_the_line()
    {
        var text = TestUserKeys.Ed25519().AuthorizedKeysLine + "\nnot a key\n" + "ssh-dss AAAAB3NzaC1kc3M= old";

        var result = SshPublicKey.ParseAuthorizedKeys(text, PublicKeySource.Admin, Now);

        Assert.Single(result.Keys);
        Assert.Equal(2, result.Errors.Count);
        Assert.StartsWith("Line 2:", result.Errors[0]);
        Assert.StartsWith("Line 3:", result.Errors[1]);
        Assert.Contains("DSA", result.Errors[1]);
    }

    [Theory]
    [InlineData("from=\"10.0.0.0/8\" ")]
    [InlineData("restrict ")]
    [InlineData("no-pty,command=\"/bin/true\" ")]
    public void Authorized_keys_options_are_refused_with_a_message(string options)
    {
        var line = options + TestUserKeys.Ed25519().AuthorizedKeysLine;

        var ex = Assert.Throws<PublicKeyFormatException>(() => Parse(line));

        Assert.Contains("options", ex.Message);
    }

    [Theory]
    [InlineData("ssh-ed25519-cert-v01@openssh.com AAAA", "certificates")]
    [InlineData("sk-ssh-ed25519@openssh.com AAAA", "Security keys")]
    [InlineData("ssh-dss AAAA", "DSA")]
    [InlineData("ssh-ed25519", "no key data")]
    [InlineData("ssh-ed25519 !!!", "base64")]
    [InlineData("ssh-ed25519 AAAA", "truncated")]
    [InlineData("hello world", "not a public key")]
    public void Unsupported_or_broken_keys_are_refused(string line, string message)
    {
        var ex = Assert.Throws<PublicKeyFormatException>(() => Parse(line));

        Assert.Contains(message, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_line_whose_type_does_not_match_the_key_data_is_refused()
    {
        var ed25519 = TestUserKeys.Ed25519().Entry.KeyBase64;

        var ex = Assert.Throws<PublicKeyFormatException>(() => Parse("ecdsa-sha2-nistp256 " + ed25519));

        Assert.Contains("ssh-ed25519", ex.Message);
    }

    [Fact]
    public void Extra_bytes_after_the_key_are_refused()
    {
        var blob = TestUserKeys.Ed25519().Blob.Concat(new byte[] { 0, 0, 0, 0 }).ToArray();

        Assert.Throws<PublicKeyFormatException>(() => SshPublicKey.FromBlob(blob, null, PublicKeySource.Admin, Now));
    }

    [Fact]
    public void An_ed25519_key_with_a_wrong_length_is_refused()
    {
        var blob = Blob(Encoding.ASCII.GetBytes("ssh-ed25519"), new byte[31]);

        Assert.Throws<PublicKeyFormatException>(() => SshPublicKey.FromBlob(blob, null, PublicKeySource.Admin, Now));
    }

    [Fact]
    public void An_rsa_key_below_2048_bits_is_refused()
    {
        using var rsa = new RSACryptoServiceProvider(1024);

        var ex = Assert.Throws<PublicKeyFormatException>(() =>
            SshPublicKey.FromRsa(rsa.ExportParameters(false), null, PublicKeySource.Admin, Now));

        Assert.Contains("1024 bits", ex.Message);
    }

    [Fact]
    public void The_old_csp_blob_of_a_user_becomes_an_ssh_rsa_entry_of_the_same_key_whatever_its_size()
    {
        using var rsa = new RSACryptoServiceProvider(1024);
        var csp = Convert.ToBase64String(rsa.ExportCspBlob(false));

        var entry = SshPublicKey.FromLegacyCspBlob(csp, Now);

        Assert.Equal("ssh-rsa", entry.KeyType);
        Assert.Equal(Convert.ToBase64String(SshPublicKey.RsaBlob(rsa.ExportParameters(false))), entry.KeyBase64);
        Assert.Equal(PublicKeySource.Admin, entry.Source);
        Assert.Equal(Now, entry.AddedAt);
    }

    [Theory]
    [InlineData("not base64!")]
    [InlineData("AAAA")]
    public void An_old_key_that_cannot_be_read_is_refused(string stored)
    {
        Assert.Throws<PublicKeyFormatException>(() => SshPublicKey.FromLegacyCspBlob(stored, Now));
    }

    [Fact]
    public void An_entry_matches_only_its_whole_blob()
    {
        var key = TestUserKeys.Ed25519();
        var other = TestUserKeys.Ed25519();
        var blob = key.Blob;
        var changedLastByte = (byte[])blob.Clone();
        changedLastByte[^1] ^= 1;

        Assert.True(key.Entry.Matches(blob));
        Assert.False(key.Entry.Matches(other.Blob));
        Assert.False(key.Entry.Matches(changedLastByte));
        Assert.False(key.Entry.Matches(blob.AsSpan(0, blob.Length - 1)));
        Assert.False(new PublicKeyEntry { KeyBase64 = "not base64!" }.Matches(blob));
    }

    [Fact]
    public void An_entry_expires_at_its_expiry_time()
    {
        var entry = new PublicKeyEntry { ExpiresAt = Now };

        Assert.False(entry.IsExpired(Now.AddTicks(-1)));
        Assert.True(entry.IsExpired(Now));
        Assert.False(new PublicKeyEntry().IsExpired(DateTime.MaxValue));
    }

    private static byte[] Blob(params byte[][] strings)
    {
        using var stream = new MemoryStream();
        foreach (var value in strings)
        {
            stream.Write(new[] { (byte)(value.Length >> 24), (byte)(value.Length >> 16), (byte)(value.Length >> 8), (byte)value.Length });
            stream.Write(value);
        }
        return stream.ToArray();
    }
}
