using System.Security.Cryptography;
using FreeSftpSharp.Tests.Infrastructure;
using FxSsh.SshServerModule;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>
/// <see cref="HostKeys"/>: the stored RSA host key (a base64 CSP blob, as older versions saved it) is converted
/// in memory and registered as rsa-sha2-512/256, and an ECDSA P-256 key is made once and saved.
/// </summary>
public sealed class HostKeysTests
{
    [Fact]
    public void Csp_blob_converts_to_a_pem_key_with_the_same_rsa_key()
    {
        using var csp = new RSACryptoServiceProvider(2048);
        var blob = Convert.ToBase64String(csp.ExportCspBlob(true));

        var pem = HostKeys.RsaKeyToPem(blob);

        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pem);
        using var converted = RSA.Create();
        converted.ImportFromPem(pem);
        Assert.Equal(csp.ExportParameters(false).Modulus, converted.ExportParameters(false).Modulus);
        Assert.Equal(csp.ExportParameters(false).Exponent, converted.ExportParameters(false).Exponent);
        // The private key is there too: a signature made with the converted key verifies with the original key.
        var data = "host key"u8.ToArray();
        var signature = converted.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(csp.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void A_pem_key_is_accepted_as_it_is()
    {
        using var rsa = RSA.Create(2048);
        var pem = HostKeys.RsaKeyToPem(rsa.ExportRSAPrivateKeyPem());

        using var converted = RSA.Create();
        converted.ImportFromPem(pem);
        Assert.Equal(rsa.ExportParameters(false).Modulus, converted.ExportParameters(false).Modulus);
    }

    [Fact]
    public void A_csp_blob_without_the_private_key_is_rejected()
    {
        using var csp = new RSACryptoServiceProvider(2048);
        var publicOnly = Convert.ToBase64String(csp.ExportCspBlob(false));

        Assert.Throws<InvalidOperationException>(() => HostKeys.RsaKeyToPem(publicOnly));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void A_missing_rsa_key_is_rejected(string? key)
    {
        Assert.Throws<InvalidOperationException>(() => HostKeys.RsaKeyToPem(key!));
    }

    [Fact]
    public void Only_sha2_rsa_and_ecdsa_host_key_algorithms_are_registered()
    {
        var repository = CreateRepository(ecdsaKey: null);

        var algorithms = HostKeys.Load(repository).Select(k => k.Algorithm).ToArray();

        Assert.Equal(new[] { "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256" }, algorithms);
        Assert.DoesNotContain("ssh-rsa", algorithms);
    }

    [Fact]
    public void Settings_without_an_ecdsa_key_get_a_new_p256_key_that_is_saved()
    {
        // Like a config.db made by an older version: only ServerRsaKey is set.
        var repository = CreateRepository(ecdsaKey: null);

        var ecdsa = HostKeys.Load(repository).Single(k => k.Algorithm == "ecdsa-sha2-nistp256");

        Assert.False(string.IsNullOrWhiteSpace(repository.ServerSettings.ServerEcdsaKey));
        Assert.Equal(repository.ServerSettings.ServerEcdsaKey, ecdsa.Pem);
        using var key = ECDsa.Create();
        key.ImportFromPem(ecdsa.Pem);
        Assert.Equal(256, key.KeySize);
    }

    [Fact]
    public void A_saved_ecdsa_key_is_used_again()
    {
        var saved = FxSsh.KeyGenerator.GenerateECDsaKeyPem("nistp256");
        var repository = CreateRepository(saved);

        var first = HostKeys.Load(repository).Single(k => k.Algorithm == "ecdsa-sha2-nistp256");
        var second = HostKeys.Load(repository).Single(k => k.Algorithm == "ecdsa-sha2-nistp256");

        Assert.Equal(saved, first.Pem);
        Assert.Equal(saved, second.Pem);
    }

    [Fact]
    public void The_rsa_key_is_the_stored_key()
    {
        var repository = CreateRepository(ecdsaKey: null);
        using var stored = new RSACryptoServiceProvider();
        stored.ImportCspBlob(Convert.FromBase64String(repository.ServerSettings.ServerRsaKey));

        foreach (var hostKey in HostKeys.Load(repository).Where(k => k.Algorithm.StartsWith("rsa-sha2-")))
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(hostKey.Pem);
            Assert.Equal(stored.ExportParameters(false).Modulus, rsa.ExportParameters(false).Modulus);
        }
    }

    private static InMemorySettingsRepository CreateRepository(string? ecdsaKey)
    {
        return new InMemorySettingsRepository(new ServerSettings
        {
            ServerRsaKey = TestCredentials.HostKey,
            ServerEcdsaKey = ecdsaKey!,
        });
    }
}
