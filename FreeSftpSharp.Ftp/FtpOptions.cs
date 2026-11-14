using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;

namespace FreeSftpSharp.Ftp;

/// <summary>How the FTP server uses TLS (RFC 4217, explicit TLS with <c>AUTH TLS</c>).</summary>
public enum FtpTlsMode
{
    /// <summary>
    /// The default: a client must send <c>AUTH TLS</c> before <c>USER</c> (else 530), and every data connection is
    /// protected (<c>PROT P</c>, else 521). The password never travels in clear text.
    /// </summary>
    Required,

    /// <summary>The client chooses: plain FTP and FTPS are both accepted.</summary>
    Optional,

    /// <summary>Plain FTP only: <c>AUTH TLS</c> is refused. Passwords and files travel in clear text.</summary>
    Disabled,
}

/// <summary>The <c>Ftp:Tls</c> section.</summary>
public sealed class FtpTlsOptions
{
    /// <summary>Required (default), Optional or Disabled.</summary>
    public FtpTlsMode Mode { get; set; } = FtpTlsMode.Required;

    /// <summary>
    /// The certificate: a PKCS#12 file (.pfx/.p12, with <see cref="CertificatePassword"/>), or a PEM certificate with
    /// <see cref="CertificateKeyPath"/>. Empty: the certificate of Kestrel (<c>Kestrel:Certificates:Default</c>), and
    /// without one a self-signed certificate made at the start (for tests only; clients warn about it).
    /// </summary>
    public string? CertificatePath { get; set; }

    /// <summary>The PEM private key of a PEM <see cref="CertificatePath"/>.</summary>
    public string? CertificateKeyPath { get; set; }

    /// <summary>The password of a PKCS#12 file, or of an encrypted PEM key. A secret: it is never logged.</summary>
    public string? CertificatePassword { get; set; }
}

/// <summary>
/// The <c>Ftp</c> section of the configuration (issue #72). FTP is off by default: without <see cref="Enabled"/> no port
/// is opened.
/// </summary>
public sealed class FtpOptions
{
    public const string SectionName = "Ftp";

    /// <summary>Turns the FTP server on. Default false.</summary>
    public bool Enabled { get; set; }

    /// <summary>The port of the control connection. Default 21. 0: a free port (for tests).</summary>
    public int Port { get; set; } = 21;

    /// <summary>The local addresses to listen on. Empty (default): all addresses, IPv4 and IPv6.</summary>
    public List<string> BindAddresses { get; set; } = new();

    /// <summary>
    /// The ports of the passive data connections, "first-last", for example "50000-50100" (the default). Open them in the
    /// firewall. The server binds a passive listener only to a port in this range.
    /// </summary>
    public string PassivePortRange { get; set; } = "50000-50100";

    /// <summary>
    /// The IPv4 address that <c>PASV</c> tells the client, for a server behind NAT. Empty (default): the local address
    /// of the control connection. <c>EPSV</c> sends only the port, so it needs no address.
    /// </summary>
    public string? PassiveExternalAddress { get; set; }

    /// <summary>
    /// Allow active mode (<c>PORT</c>, <c>EPRT</c>): the server connects to the client. Default false. Even then the
    /// server connects only to the address of the control connection and to a port of 1024 or higher (no FTP bounce).
    /// </summary>
    public bool AllowActiveMode { get; set; }

    /// <summary>The text of the 220 greeting. One line.</summary>
    public string Banner { get; set; } = "FreeSftpSharp FTP server ready.";

    /// <summary>A control connection without a command for this many seconds is closed (421). Default 300.</summary>
    public int IdleTimeoutSeconds { get; set; } = 300;

    /// <summary>How long the server waits for a data connection, and for data on it. Default 30 seconds.</summary>
    public int DataTimeoutSeconds { get; set; } = 30;

    /// <summary>The most control connections from one client address at the same time. Default 10. 0: no limit.</summary>
    public int MaxConnectionsPerIp { get; set; } = 10;

    /// <summary>Failed logins on one control connection before the server closes it. Default 3.</summary>
    public int MaxLoginAttempts { get; set; } = 3;

    public FtpTlsOptions Tls { get; set; } = new();

    /// <summary>The longest command line in bytes, CRLF included. A longer line closes the connection.</summary>
    internal const int MaxCommandLineBytes = 4096;

    /// <summary>The parsed <see cref="PassivePortRange"/>.</summary>
    internal (int First, int Last) PassivePorts => TryParseRange(PassivePortRange, out var range)
        ? range
        : throw new InvalidOperationException("Ftp:PassivePortRange is not valid.");

    internal IPAddress? ExternalAddress => string.IsNullOrWhiteSpace(PassiveExternalAddress) ? null : IPAddress.Parse(PassiveExternalAddress.Trim());

    internal static bool TryParseRange(string? text, out (int First, int Last) range)
    {
        range = default;
        var parts = (text ?? "").Split('-', StringSplitOptions.TrimEntries);
        if (parts.Length != 2
            || !int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var first)
            || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var last)
            || first < 1024 || last > 65535 || first > last)
            return false;
        range = (first, last);
        return true;
    }
}

/// <summary>Checks <see cref="FtpOptions"/> at the start. Only an enabled server is checked.</summary>
public sealed class FtpOptionsValidator : IValidateOptions<FtpOptions>
{
    public ValidateOptionsResult Validate(string? name, FtpOptions options)
    {
        if (!options.Enabled)
            return ValidateOptionsResult.Success;
        var problems = new List<string>();
        if (options.Port is < 0 or > 65535)
            problems.Add("Ftp:Port must be between 0 and 65535.");
        if (!FtpOptions.TryParseRange(options.PassivePortRange, out _))
            problems.Add("Ftp:PassivePortRange must be \"first-last\" with ports from 1024 to 65535, for example \"50000-50100\".");
        if (!string.IsNullOrWhiteSpace(options.PassiveExternalAddress)
            && (!IPAddress.TryParse(options.PassiveExternalAddress.Trim(), out var external) || external.AddressFamily != AddressFamily.InterNetwork))
            problems.Add("Ftp:PassiveExternalAddress must be an IPv4 address.");
        if (string.IsNullOrWhiteSpace(options.Banner) || options.Banner.IndexOfAny(['\r', '\n']) >= 0)
            problems.Add("Ftp:Banner must be one line of text.");
        if (options.IdleTimeoutSeconds <= 0 || options.DataTimeoutSeconds <= 0)
            problems.Add("Ftp:IdleTimeoutSeconds and Ftp:DataTimeoutSeconds must be greater than 0.");
        if (options.MaxConnectionsPerIp < 0)
            problems.Add("Ftp:MaxConnectionsPerIp must be 0 (no limit) or more.");
        if (options.MaxLoginAttempts <= 0)
            problems.Add("Ftp:MaxLoginAttempts must be greater than 0.");
        if (!string.IsNullOrWhiteSpace(options.Tls.CertificatePath) && !File.Exists(options.Tls.CertificatePath))
            problems.Add("Ftp:Tls:CertificatePath does not exist.");
        if (!string.IsNullOrWhiteSpace(options.Tls.CertificateKeyPath) && !File.Exists(options.Tls.CertificateKeyPath))
            problems.Add("Ftp:Tls:CertificateKeyPath does not exist.");
        return problems.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(problems);
    }
}
