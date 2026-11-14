using System.Globalization;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.WebDav;

/// <summary>The XML of WebDAV requests and responses, and the values of the live properties.</summary>
internal static class WebDavXml
{
    public static readonly XNamespace Dav = "DAV:";

    /// <summary>The properties of the Windows client (Win32LastModifiedTime and others).</summary>
    public static readonly XNamespace Ms = "urn:schemas-microsoft-com:";

    /// <summary>The largest XML body of a request (PROPFIND, PROPPATCH, LOCK).</summary>
    public const int MaxBodyBytes = 1024 * 1024;

    /// <summary>The XML body of the request; null when it is empty. Throws <see cref="XmlException"/> for a bad or too large body.</summary>
    public static async Task<XDocument?> ReadBodyAsync(HttpRequest request, CancellationToken ct)
    {
        if (request.ContentLength == 0)
            return null;
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await request.Body.ReadAsync(chunk, ct)) > 0)
        {
            if (buffer.Length + read > MaxBodyBytes)
                throw new XmlException("The XML body is too large.");
            buffer.Write(chunk, 0, read);
        }
        if (buffer.Length == 0)
            return null;
        buffer.Position = 0;
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, IgnoreComments = true };
        using var reader = XmlReader.Create(buffer, settings);
        return XDocument.Load(reader);
    }

    /// <summary>Writes an XML response with <paramref name="status"/>.</summary>
    public static async Task WriteAsync(HttpResponse response, int status, XElement root)
    {
        response.StatusCode = status;
        response.ContentType = "application/xml; charset=utf-8";
        var document = new XDocument(new XDeclaration("1.0", "utf-8", null), root);
        using var buffer = new MemoryStream();
        using (var writer = XmlWriter.Create(buffer, new XmlWriterSettings { Encoding = new UTF8Encoding(false), Async = true }))
            document.Save(writer);
        response.ContentLength = buffer.Length;
        buffer.Position = 0;
        await buffer.CopyToAsync(response.Body, response.HttpContext.RequestAborted);
    }

    /// <summary>A DAV:error body with one precondition element, for example "lock-token-submitted".</summary>
    public static XElement Error(string condition, params string[] hrefs) =>
        new(Dav + "error", new XElement(Dav + condition, hrefs.Select(h => new XElement(Dav + "href", h))));

    /// <summary>The root element with the DAV namespace prefix "D".</summary>
    public static XElement Root(string name, params object[] content) =>
        new(Dav + name, new XAttribute(XNamespace.Xmlns + "D", Dav.NamespaceName), content);

    public static string Status(int code) => $"HTTP/1.1 {code} {ReasonPhrase(code)}";

    public static string ReasonPhrase(int code) =>
        ReasonPhrases.GetReasonPhrase(code) is { Length: > 0 } phrase ? phrase : "Error";

    /// <summary>The strong entity tag of an entry: its size and its last write time.</summary>
    public static string ETagOf(FileSystemEntry entry) =>
        "\"" + entry.Size.ToString("x", CultureInfo.InvariantCulture) + "-" + entry.LastWriteTimeUtc.Ticks.ToString("x", CultureInfo.InvariantCulture) + "\"";

    /// <summary>An HTTP date (RFC 1123), for getlastmodified and Last-Modified.</summary>
    public static string HttpDate(DateTime utc) => DateTime.SpecifyKind(utc, DateTimeKind.Utc).ToString("R", CultureInfo.InvariantCulture);

    /// <summary>An ISO 8601 date, for creationdate.</summary>
    public static string IsoDate(DateTime utc) => DateTime.SpecifyKind(utc, DateTimeKind.Utc).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>Reads an HTTP date or an ISO 8601 date (some clients send that in PROPPATCH).</summary>
    public static bool TryParseDate(string? text, out DateTime utc)
    {
        utc = default;
        if (string.IsNullOrWhiteSpace(text))
            return false;
        if (DateTime.TryParseExact(text.Trim(), "R", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out utc))
            return true;
        if (DateTimeOffset.TryParse(text.Trim(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var offset))
        {
            utc = offset.UtcDateTime;
            return true;
        }
        return false;
    }
}
