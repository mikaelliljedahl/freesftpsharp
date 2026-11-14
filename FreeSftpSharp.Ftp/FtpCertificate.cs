using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FreeSftpSharp.Ftp;

/// <summary>
/// The TLS certificate of the FTP server (<see cref="FtpTlsOptions"/>), loaded once. Without a configured certificate
/// (and no Kestrel certificate) a self-signed one is made at the start, so FTPS works on a developer machine.
/// </summary>
internal sealed class FtpCertificate : IDisposable
{
    private readonly Lazy<X509Certificate2?> _certificate;
    private readonly Lazy<SslServerAuthenticationOptions?> _options;

    public FtpCertificate(IOptions<FtpOptions> options, ILogger<FtpCertificate> logger)
    {
        var tls = options.Value.Tls;
        _certificate = new Lazy<X509Certificate2?>(() => tls.Mode == FtpTlsMode.Disabled ? null : Load(tls, logger));
        _options = new Lazy<SslServerAuthenticationOptions?>(() => _certificate.Value is { } certificate
            ? new SslServerAuthenticationOptions
            {
                // One context for the control and data connections, so that a client can resume the TLS session.
                ServerCertificateContext = SslStreamCertificateContext.Create(certificate, null),
                ClientCertificateRequired = false,
                AllowTlsResume = true,
            }
            : null);
    }

    /// <summary>The TLS options of the server side, or null when TLS is off.</summary>
    public SslServerAuthenticationOptions? ServerOptions => _options.Value;

    internal static X509Certificate2 Load(FtpTlsOptions tls, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(tls.CertificatePath))
        {
            logger.LogWarning("FTPS uses a self-signed certificate made at the start; clients will warn about it. Set Ftp:Tls:CertificatePath for a real one.");
            return SelfSigned();
        }

        X509Certificate2 loaded;
        if (!string.IsNullOrWhiteSpace(tls.CertificateKeyPath))
            loaded = string.IsNullOrEmpty(tls.CertificatePassword)
                ? X509Certificate2.CreateFromPemFile(tls.CertificatePath, tls.CertificateKeyPath)
                : X509Certificate2.CreateFromEncryptedPemFile(tls.CertificatePath, tls.CertificatePassword, tls.CertificateKeyPath);
        else if (IsPem(tls.CertificatePath))
            loaded = X509Certificate2.CreateFromPemFile(tls.CertificatePath);
        else
            loaded = X509CertificateLoader.LoadPkcs12FromFile(tls.CertificatePath, tls.CertificatePassword);

        if (!loaded.HasPrivateKey)
        {
            loaded.Dispose();
            throw new InvalidOperationException("The FTP certificate has no private key. Set Ftp:Tls:CertificateKeyPath.");
        }
        logger.LogInformation("FTPS certificate {Subject}, valid until {NotAfter:yyyy-MM-dd}.", loaded.Subject, loaded.NotAfter);
        return Persisted(loaded);
    }

    private static bool IsPem(string path)
    {
        using var reader = new StreamReader(path);
        var buffer = new char[64];
        var read = reader.Read(buffer, 0, buffer.Length);
        return new string(buffer, 0, read).Contains("-----BEGIN", StringComparison.Ordinal);
    }

    private static X509Certificate2 SelfSigned()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=FreeSftpSharp FTP", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        names.AddIpAddress(System.Net.IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        var now = DateTimeOffset.UtcNow;
        using var certificate = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));
        return Persisted(certificate);
    }

    /// <summary>A copy with a key that SslStream can use on every platform (Windows cannot use an ephemeral PEM key).</summary>
    private static X509Certificate2 Persisted(X509Certificate2 certificate)
    {
        var copy = X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pkcs12), null);
        certificate.Dispose();
        return copy;
    }

    public void Dispose()
    {
        if (_certificate.IsValueCreated)
            _certificate.Value?.Dispose();
    }
}
