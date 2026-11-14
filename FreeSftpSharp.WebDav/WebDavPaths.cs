using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.WebDav;

/// <summary>
/// Converts between the URLs of the WebDAV clients and the virtual paths of the user's <see cref="IFileSystem"/>. A URL
/// that names "." or ".." or has an encoded separator, a backslash or a NUL in a segment is refused (never normalized),
/// so a path can never be read in another way than the client wrote it.
/// </summary>
internal sealed class WebDavPaths
{
    private readonly string[] _prefix;

    public WebDavPaths(string normalizedPrefix)
    {
        Prefix = normalizedPrefix == "/" ? "" : normalizedPrefix;
        _prefix = Prefix.Split('/', StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>The path of the user root in URLs, without "/" at the end ("" for "/").</summary>
    public string Prefix { get; }

    /// <summary>True when the decoded request path is under the prefix.</summary>
    public bool IsUnderPrefix(PathString path)
    {
        var value = path.Value ?? "/";
        if (Prefix.Length == 0)
            return true;
        return value.Equals(Prefix, StringComparison.OrdinalIgnoreCase)
            || value.StartsWith(Prefix + "/", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The virtual path of the request, from the raw request target; null when the target is refused.</summary>
    public string? FromRequest(HttpRequest request)
    {
        var raw = request.HttpContext.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(raw) || !raw.StartsWith('/'))
            raw = request.PathBase.Add(request.Path).ToUriComponent();
        var query = raw.IndexOfAny(['?', '#']);
        if (query >= 0)
            raw = raw[..query];
        return FromEscapedPath(raw);
    }

    /// <summary>
    /// The virtual path of a Destination header (an absolute URL or an absolute path). Null when it is refused;
    /// <paramref name="otherServer"/> is true when the URL names another host or a path outside the prefix (502).
    /// </summary>
    public string? FromDestination(string? destination, HttpRequest request, out bool otherServer)
    {
        otherServer = false;
        if (string.IsNullOrWhiteSpace(destination))
            return null;
        string escapedPath;
        if (Uri.TryCreate(destination, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https")
        {
            var sameHost = string.Equals(uri.Authority, request.Host.Value, StringComparison.OrdinalIgnoreCase)
                || (string.Equals(uri.Host, request.Host.Host, StringComparison.OrdinalIgnoreCase)
                    && (request.Host.Port ?? DefaultPort(request.Scheme)) == uri.Port);
            if (!sameHost)
            {
                otherServer = true;
                return null;
            }
            // The path as sent: Uri would remove dot segments, which are refused here instead.
            var afterAuthority = destination.IndexOf('/', destination.IndexOf("//", StringComparison.Ordinal) + 2);
            escapedPath = afterAuthority < 0 ? "/" : destination[afterAuthority..];
            var end = escapedPath.IndexOfAny(['?', '#']);
            if (end >= 0)
                escapedPath = escapedPath[..end];
        }
        else if (destination.StartsWith('/'))
            escapedPath = destination;
        else
            return null;

        var path = FromEscapedPath(escapedPath, out var outside);
        otherServer = outside;
        return path;
    }

    private string? FromEscapedPath(string escaped) => FromEscapedPath(escaped, out _);

    private string? FromEscapedPath(string escaped, out bool outsidePrefix)
    {
        outsidePrefix = false;
        var segments = new List<string>();
        foreach (var part in escaped.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            string segment;
            try
            {
                segment = Uri.UnescapeDataString(part);
            }
            catch (UriFormatException)
            {
                return null;
            }
            if (segment is "." or ".." || segment.IndexOfAny(['/', '\\', '\0']) >= 0)
                return null;
            segments.Add(segment);
        }

        if (segments.Count < _prefix.Length
            || !_prefix.Select((p, i) => string.Equals(p, segments[i], StringComparison.OrdinalIgnoreCase)).All(x => x))
        {
            outsidePrefix = true;
            return null;
        }
        return "/" + string.Join('/', segments.Skip(_prefix.Length));
    }

    /// <summary>The escaped URL path of a virtual path, with "/" at the end for a collection.</summary>
    public string ToHref(string virtualPath, bool isCollection)
    {
        var escaped = string.Join('/', virtualPath.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(Uri.EscapeDataString));
        var href = Prefix + "/" + escaped;
        if (isCollection && !href.EndsWith('/'))
            href += "/";
        return href;
    }

    private static int DefaultPort(string scheme) => scheme == "https" ? 443 : 80;
}
