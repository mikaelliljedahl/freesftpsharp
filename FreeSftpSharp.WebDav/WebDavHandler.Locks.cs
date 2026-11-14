using System.Globalization;
using System.Xml.Linq;
using Microsoft.AspNetCore.Http;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.WebDav;

/// <summary>LOCK and UNLOCK (RFC 4918 sections 9.10 and 9.11): write locks, exclusive or shared, depth 0 or infinity, with timeouts.</summary>
internal sealed partial class WebDavHandler
{
    private async Task LockAsync(WebDavRequest request)
    {
        var timeout = ParseTimeout(request.Request.Headers["Timeout"].ToString());
        var body = await WebDavXml.ReadBodyAsync(request.Request, request.Aborted);
        if (body?.Root == null)
        {
            await RefreshLockAsync(request, timeout);
            return;
        }

        var info = body.Root;
        if (info.Name != WebDavXml.Dav + "lockinfo" || info.Element(WebDavXml.Dav + "locktype")?.Element(WebDavXml.Dav + "write") == null)
        {
            request.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var scope = info.Element(WebDavXml.Dav + "lockscope");
        var exclusive = scope?.Element(WebDavXml.Dav + "exclusive") != null;
        if (!exclusive && scope?.Element(WebDavXml.Dav + "shared") == null)
        {
            request.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var depth = request.Request.Headers["Depth"].ToString().Trim();
        if (depth.Length > 0 && depth != "0" && !depth.Equals("infinity", StringComparison.OrdinalIgnoreCase))
        {
            request.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var owner = info.Element(WebDavXml.Dav + "owner")?.ToString(SaveOptions.DisableFormatting);

        var fs = request.FileSystem;
        var entry = await fs.StatAsync(request.Path, followLinks: true, request.Aborted);
        var infinite = depth != "0" && entry is { IsDirectory: true };
        if (entry == null)
        {
            // RFC 4918 section 7.3: a lock on an unmapped URL makes an empty resource.
            if (await fs.StatAsync(VirtualPath.GetParent(request.Path), followLinks: true, request.Aborted) is not { IsDirectory: true })
            {
                request.Response.StatusCode = StatusCodes.Status409Conflict;
                return;
            }
            if (!await CheckLocksAsync(request, request.Path, recursive: false, parentMembership: true))
                return;
        }

        var (created, conflict) = _locks.TryLock(request.Owner, request.Path, exclusive, infinite, owner, timeout);
        if (created == null)
        {
            await WebDavXml.WriteAsync(request.Response, StatusCodes.Status423Locked, WebDavXml.Root("error",
                new XElement(WebDavXml.Dav + "no-conflicting-lock",
                    new XElement(WebDavXml.Dav + "href", _paths.ToHref(conflict!.Root, conflict.Infinite)))));
            return;
        }

        if (entry == null)
        {
            try
            {
                var handle = await fs.OpenAsync(request.Path, FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Exclusive, null, request.Aborted);
                await handle.DisposeAsync();
            }
            catch
            {
                _locks.Unlock(request.Owner, request.Path, created.Token);
                throw;
            }
        }

        request.Response.Headers["Lock-Token"] = "<" + created.Token + ">";
        await WebDavXml.WriteAsync(request.Response, entry == null ? StatusCodes.Status201Created : StatusCodes.Status200OK,
            WebDavXml.Root("prop", new XElement(LockDiscovery, ActiveLock(created))));
    }

    /// <summary>A LOCK without a body refreshes the lock whose token is in the If header.</summary>
    private async Task RefreshLockAsync(WebDavRequest request, TimeSpan timeout)
    {
        foreach (var token in request.SubmittedTokens)
        {
            var refreshed = _locks.Refresh(request.Owner, request.Path, token, timeout);
            if (refreshed == null)
                continue;
            await WebDavXml.WriteAsync(request.Response, StatusCodes.Status200OK,
                WebDavXml.Root("prop", new XElement(LockDiscovery, ActiveLock(refreshed))));
            return;
        }
        if (request.If == null)
        {
            await WriteTextAsync(request.Response, StatusCodes.Status400BadRequest, "A lock refresh needs the lock token in the If header.");
            return;
        }
        await WebDavXml.WriteAsync(request.Response, StatusCodes.Status412PreconditionFailed, WebDavXml.Error("lock-token-matches-request-uri"));
    }

    private async Task UnlockAsync(WebDavRequest request)
    {
        var header = request.Request.Headers["Lock-Token"].ToString().Trim();
        if (header.Length < 3 || header[0] != '<' || header[^1] != '>')
        {
            await WriteTextAsync(request.Response, StatusCodes.Status400BadRequest, "UNLOCK needs a Lock-Token header.");
            return;
        }
        if (!_locks.Unlock(request.Owner, request.Path, header[1..^1]))
        {
            await WebDavXml.WriteAsync(request.Response, StatusCodes.Status409Conflict, WebDavXml.Error("lock-token-matches-request-uri"));
            return;
        }
        request.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    /// <summary>The Timeout header ("Second-600", "Infinite", or a list): the first value, limited to the maximum.</summary>
    private TimeSpan ParseTimeout(string header)
    {
        var max = TimeSpan.FromSeconds(_options.MaxLockTimeoutSeconds);
        foreach (var part in header.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.StartsWith("Second-", StringComparison.OrdinalIgnoreCase)
                && long.TryParse(part[7..], NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) && seconds > 0)
                return TimeSpan.FromSeconds(Math.Min(seconds, (long)max.TotalSeconds));
            if (part.Equals("Infinite", StringComparison.OrdinalIgnoreCase))
                break;
        }
        var fallback = TimeSpan.FromSeconds(_options.DefaultLockTimeoutSeconds);
        return fallback < max ? fallback : max;
    }

    private XElement ActiveLock(WebDavLock l)
    {
        var active = new XElement(WebDavXml.Dav + "activelock",
            new XElement(WebDavXml.Dav + "locktype", new XElement(WebDavXml.Dav + "write")),
            new XElement(WebDavXml.Dav + "lockscope", new XElement(WebDavXml.Dav + (l.Exclusive ? "exclusive" : "shared"))),
            new XElement(WebDavXml.Dav + "depth", l.Infinite ? "infinity" : "0"));
        if (l.OwnerXml != null)
        {
            try
            {
                active.Add(XElement.Parse(l.OwnerXml));
            }
            catch (System.Xml.XmlException)
            {
                // Stored from a parsed element, so this does not happen; the lock is still valid without its owner.
            }
        }
        active.Add(
            new XElement(WebDavXml.Dav + "timeout", "Second-" + ((long)l.Timeout.TotalSeconds).ToString(CultureInfo.InvariantCulture)),
            new XElement(WebDavXml.Dav + "locktoken", new XElement(WebDavXml.Dav + "href", l.Token)),
            new XElement(WebDavXml.Dav + "lockroot", new XElement(WebDavXml.Dav + "href", _paths.ToHref(l.Root, l.Infinite))));
        return active;
    }
}
