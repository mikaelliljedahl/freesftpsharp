using System.Globalization;
using System.Xml.Linq;
using Microsoft.AspNetCore.Http;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.WebDav;

/// <summary>PROPFIND and PROPPATCH (RFC 4918 sections 9.1 and 9.2).</summary>
internal sealed partial class WebDavHandler
{
    private static readonly XName ResourceType = WebDavXml.Dav + "resourcetype";
    private static readonly XName CreationDate = WebDavXml.Dav + "creationdate";
    private static readonly XName DisplayName = WebDavXml.Dav + "displayname";
    private static readonly XName ContentLength = WebDavXml.Dav + "getcontentlength";
    private static readonly XName ContentType = WebDavXml.Dav + "getcontenttype";
    private static readonly XName ETag = WebDavXml.Dav + "getetag";
    private static readonly XName LastModified = WebDavXml.Dav + "getlastmodified";
    private static readonly XName SupportedLock = WebDavXml.Dav + "supportedlock";
    private static readonly XName LockDiscovery = WebDavXml.Dav + "lockdiscovery";
    private static readonly XName QuotaAvailable = WebDavXml.Dav + "quota-available-bytes";
    private static readonly XName QuotaUsed = WebDavXml.Dav + "quota-used-bytes";
    private static readonly XName Win32LastModified = WebDavXml.Ms + "Win32LastModifiedTime";
    private static readonly XName Win32LastAccess = WebDavXml.Ms + "Win32LastAccessTime";
    private static readonly XName Win32Creation = WebDavXml.Ms + "Win32CreationTime";
    private static readonly XName Win32Attributes = WebDavXml.Ms + "Win32FileAttributes";

    /// <summary>The live properties of allprop (the quota properties only when they are asked for by name, RFC 4331).</summary>
    private static readonly XName[] AllProperties =
        [ResourceType, CreationDate, DisplayName, ContentLength, ContentType, ETag, LastModified, SupportedLock, LockDiscovery];

    // ---- PROPFIND ----

    private async Task PropfindAsync(WebDavRequest request)
    {
        var depth = request.Request.Headers["Depth"].ToString().Trim();
        if (depth.Length == 0 || depth.Equals("infinity", StringComparison.OrdinalIgnoreCase))
        {
            // RFC 4918 section 9.1: a server may refuse depth infinity; a whole tree in one answer is too expensive.
            await WebDavXml.WriteAsync(request.Response, StatusCodes.Status403Forbidden, WebDavXml.Root("error",
                new XElement(WebDavXml.Dav + "propfind-finite-depth")));
            return;
        }
        if (depth is not ("0" or "1"))
        {
            request.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var body = await WebDavXml.ReadBodyAsync(request.Request, request.Aborted);
        var (namesOnly, requested) = ParsePropfind(body);
        if (requested == null)
        {
            request.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var entry = await request.FileSystem.StatAsync(request.Path, followLinks: true, request.Aborted);
        if (entry == null)
        {
            request.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var responses = new List<XElement> { await PropfindResponseAsync(request, request.Path, entry, namesOnly, requested) };
        if (depth == "1" && entry.IsDirectory)
        {
            var children = new List<FileSystemEntry>();
            await foreach (var child in request.FileSystem.ListAsync(request.Path, request.Aborted))
                children.Add(child);
            foreach (var child in children.OrderBy(c => c.Name, StringComparer.Ordinal))
                responses.Add(await PropfindResponseAsync(request, VirtualPath.Combine(request.Path, child.Name), child, namesOnly, requested));
        }
        await WebDavXml.WriteAsync(request.Response, StatusCodes.Status207MultiStatus, WebDavXml.Root("multistatus", responses));
    }

    /// <summary>
    /// The kind of PROPFIND: propname (names only), prop (the named properties) or allprop (null names; also an empty
    /// body). Returns null names and false for a body that is none of them.
    /// </summary>
    private static (bool NamesOnly, IReadOnlyList<XName>? Requested) ParsePropfind(XDocument? body)
    {
        if (body?.Root == null)
            return (false, AllProperties);
        if (body.Root.Name != WebDavXml.Dav + "propfind")
            return (false, null);
        if (body.Root.Element(WebDavXml.Dav + "propname") != null)
            return (true, AllProperties);
        if (body.Root.Element(WebDavXml.Dav + "prop") is { } prop)
            return (false, prop.Elements().Select(e => e.Name).Distinct().ToList());
        if (body.Root.Element(WebDavXml.Dav + "allprop") != null)
            return (false, AllProperties);
        return (false, null);
    }

    private async Task<XElement> PropfindResponseAsync(WebDavRequest request, string path, FileSystemEntry entry, bool namesOnly, IReadOnlyList<XName> names)
    {
        var found = new List<XElement>();
        var missing = new List<XElement>();
        foreach (var name in names)
        {
            if (namesOnly)
            {
                if (name != ContentLength && name != ContentType || !entry.IsDirectory)
                    found.Add(new XElement(name));
                continue;
            }
            var value = await PropertyAsync(request, path, entry, name);
            if (value != null)
                found.Add(value);
            else
                missing.Add(new XElement(name));
        }

        var response = new XElement(WebDavXml.Dav + "response", new XElement(WebDavXml.Dav + "href", _paths.ToHref(path, entry.IsDirectory)));
        if (found.Count > 0 || missing.Count == 0)
            response.Add(PropStat(found, StatusCodes.Status200OK));
        if (missing.Count > 0)
            response.Add(PropStat(missing, StatusCodes.Status404NotFound));
        return response;
    }

    private static XElement PropStat(IEnumerable<XElement> properties, int status) =>
        new(WebDavXml.Dav + "propstat", new XElement(WebDavXml.Dav + "prop", properties), new XElement(WebDavXml.Dav + "status", WebDavXml.Status(status)));

    /// <summary>The value of one live property, or null when the resource has no such property.</summary>
    private async Task<XElement?> PropertyAsync(WebDavRequest request, string path, FileSystemEntry entry, XName name)
    {
        if (name == ResourceType)
            return new XElement(name, entry.IsDirectory ? new XElement(WebDavXml.Dav + "collection") : null);
        if (name == CreationDate)
            return new XElement(name, WebDavXml.IsoDate(entry.LastWriteTimeUtc)); // the storage has no creation time
        if (name == DisplayName)
            return new XElement(name, path == VirtualPath.Root ? "" : entry.Name);
        if (name == ContentLength)
            return entry.IsDirectory ? null : new XElement(name, entry.Size.ToString(CultureInfo.InvariantCulture));
        if (name == ContentType)
            return entry.IsDirectory ? null : new XElement(name, ContentTypeOf(path));
        if (name == ETag)
            return new XElement(name, WebDavXml.ETagOf(entry));
        if (name == LastModified)
            return new XElement(name, WebDavXml.HttpDate(entry.LastWriteTimeUtc));
        if (name == SupportedLock)
            return new XElement(name, LockEntry("exclusive"), LockEntry("shared"));
        if (name == LockDiscovery)
            return new XElement(name, _locks.Covering(request.Owner, path).Select(ActiveLock));
        if (name == QuotaAvailable || name == QuotaUsed)
        {
            if (!entry.IsDirectory || await request.FileSystem.GetStorageSpaceAsync(path, request.Aborted) is not { } space)
                return null;
            return name == QuotaAvailable
                ? new XElement(name, space.AvailableBytes.ToString(CultureInfo.InvariantCulture))
                : new XElement(name, (space.TotalBytes > space.FreeBytes ? space.TotalBytes - space.FreeBytes : 0).ToString(CultureInfo.InvariantCulture));
        }
        return null;
    }

    private static XElement LockEntry(string scope) => new(WebDavXml.Dav + "lockentry",
        new XElement(WebDavXml.Dav + "lockscope", new XElement(WebDavXml.Dav + scope)),
        new XElement(WebDavXml.Dav + "locktype", new XElement(WebDavXml.Dav + "write")));

    // ---- PROPPATCH ----

    /// <summary>
    /// PROPPATCH. The storage keeps no dead properties, so only the modification time can be set (DAV:getlastmodified or
    /// Win32LastModifiedTime, with <see cref="StorageCapabilities.SetTimes"/>) and the access time (Win32LastAccessTime).
    /// Win32CreationTime and Win32FileAttributes, which Windows sets after each copy, are accepted and not kept. Every
    /// other property is refused with 403. The update is all or nothing: one refused property fails all (424).
    /// </summary>
    private async Task ProppatchAsync(WebDavRequest request)
    {
        var entry = await request.FileSystem.StatAsync(request.Path, followLinks: true, request.Aborted);
        if (entry == null)
        {
            request.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        var body = await WebDavXml.ReadBodyAsync(request.Request, request.Aborted);
        if (body?.Root == null || body.Root.Name != WebDavXml.Dav + "propertyupdate")
        {
            request.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        if (!await CheckLocksAsync(request, request.Path, recursive: false, parentMembership: false))
            return;

        var canSetTimes = (request.FileSystem.Capabilities & StorageCapabilities.SetTimes) != 0;
        var results = new List<(XName Name, int Status)>();
        DateTime? lastWrite = null;
        DateTime? lastAccess = null;
        foreach (var operation in body.Root.Elements())
        {
            var set = operation.Name == WebDavXml.Dav + "set";
            if (!set && operation.Name != WebDavXml.Dav + "remove")
                continue;
            foreach (var property in operation.Elements(WebDavXml.Dav + "prop").Elements())
            {
                var status = StatusCodes.Status403Forbidden;
                if (set && (property.Name == LastModified || property.Name == Win32LastModified || property.Name == Win32LastAccess))
                {
                    if (canSetTimes && WebDavXml.TryParseDate(property.Value, out var time))
                    {
                        status = StatusCodes.Status200OK;
                        if (property.Name == Win32LastAccess)
                            lastAccess = time;
                        else
                            lastWrite = time;
                    }
                    else if (canSetTimes)
                        status = StatusCodes.Status409Conflict; // not a date
                }
                else if (set && (property.Name == Win32Creation || property.Name == Win32Attributes))
                    status = StatusCodes.Status200OK;
                results.Add((property.Name, status));
            }
        }

        var failed = results.Any(r => r.Status != StatusCodes.Status200OK);
        if (failed)
            results = results.Select(r => r.Status == StatusCodes.Status200OK ? (r.Name, StatusCodes.Status424FailedDependency) : r).ToList();
        else if (lastWrite != null || lastAccess != null)
            await request.FileSystem.SetAttributesAsync(request.Path,
                new FileAttributesUpdate { LastWriteTimeUtc = lastWrite, LastAccessTimeUtc = lastAccess }, request.Aborted);

        var response = new XElement(WebDavXml.Dav + "response", new XElement(WebDavXml.Dav + "href", _paths.ToHref(request.Path, entry.IsDirectory)));
        foreach (var group in results.GroupBy(r => r.Status))
            response.Add(PropStat(group.Select(r => new XElement(r.Name)), group.Key));
        await WebDavXml.WriteAsync(request.Response, StatusCodes.Status207MultiStatus, WebDavXml.Root("multistatus", response));
    }
}
