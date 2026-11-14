using Microsoft.Extensions.Options;

namespace FreeSftpSharp.WebDav;

/// <summary>
/// The <c>WebDav</c> section of the configuration (issue #71). WebDAV is off by default: without <see cref="Enabled"/>
/// the web host has no WebDAV path and opens no port.
/// </summary>
public sealed class WebDavOptions
{
    public const string SectionName = "WebDav";

    /// <summary>Turns WebDAV on. Default false.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// The path of the user root, for example "/dav" (default): <c>https://server/dav/</c> is "/" of the user. "/" is
    /// allowed only with a <see cref="Port"/>, so it never hides the admin UI.
    /// </summary>
    public string Path { get; set; } = "/dav";

    /// <summary>
    /// 0 (default): WebDAV answers on every endpoint of the web host, under <see cref="Path"/>. A port: WebDAV answers only
    /// requests that came to this local port, and every request to that port is a WebDAV request (the admin UI is not
    /// reachable on it). The port itself is a Kestrel endpoint (<c>Kestrel:Endpoints</c>, with its certificate).
    /// </summary>
    public int Port { get; set; }

    /// <summary>
    /// Allow Basic authentication over plain HTTP from other hosts than loopback. Default false: such a request gets 403.
    /// Behind a TLS proxy, use the forwarded headers of ASP.NET Core instead, so the request counts as HTTPS.
    /// </summary>
    public bool AllowInsecureHttp { get; set; }

    /// <summary>The realm of the Basic authentication challenge.</summary>
    public string Realm { get; set; } = "FreeSftpSharp";

    /// <summary>
    /// A WebDAV session (one entry in the connection registry, one login event) ends after this many seconds without a
    /// request. Default 300.
    /// </summary>
    public int SessionIdleTimeoutSeconds { get; set; } = 300;

    /// <summary>The timeout of a lock when the client asks for none or for "Infinite". Default 600.</summary>
    public int DefaultLockTimeoutSeconds { get; set; } = 600;

    /// <summary>The longest timeout of a lock. Default 3600.</summary>
    public int MaxLockTimeoutSeconds { get; set; } = 3600;

    /// <summary>The largest PUT body in bytes. Null (default): no limit of the protocol (the quota of the user still applies).</summary>
    public long? MaxUploadBytes { get; set; }

    /// <summary>The normalized path: starts with "/", no "/" at the end (except "/" itself).</summary>
    internal string NormalizedPath => Path.Length > 1 ? Path.TrimEnd('/') : Path;
}

/// <summary>Checks <see cref="WebDavOptions"/> at the start.</summary>
public sealed class WebDavOptionsValidator : IValidateOptions<WebDavOptions>
{
    public ValidateOptionsResult Validate(string? name, WebDavOptions options)
    {
        var problems = new List<string>();
        if (string.IsNullOrWhiteSpace(options.Path) || !options.Path.StartsWith('/') || options.Path.Contains('\\')
            || options.Path.Split('/').Any(s => s is "." or ".."))
            problems.Add("WebDav:Path must start with '/', for example \"/dav\".");
        else if (options.NormalizedPath == "/" && options.Port == 0)
            problems.Add("WebDav:Path \"/\" needs WebDav:Port, so that WebDAV does not hide the admin UI.");
        if (options.Port is < 0 or > 65535)
            problems.Add("WebDav:Port must be between 0 and 65535.");
        if (options.SessionIdleTimeoutSeconds <= 0)
            problems.Add("WebDav:SessionIdleTimeoutSeconds must be greater than 0.");
        if (options.DefaultLockTimeoutSeconds <= 0 || options.MaxLockTimeoutSeconds <= 0)
            problems.Add("WebDav:DefaultLockTimeoutSeconds and WebDav:MaxLockTimeoutSeconds must be greater than 0.");
        if (options.MaxUploadBytes is <= 0)
            problems.Add("WebDav:MaxUploadBytes must be greater than 0, or empty for no limit.");
        if (string.IsNullOrWhiteSpace(options.Realm) || options.Realm.Contains('"'))
            problems.Add("WebDav:Realm must not be empty or contain '\"'.");
        return problems.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(problems);
    }
}
