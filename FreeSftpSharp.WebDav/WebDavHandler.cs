using System.Net;
using System.Xml;
using FxSsh.SshServerModule.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.WebDav;

/// <summary>One WebDAV request after the login: the session, the virtual path and the If header.</summary>
internal sealed class WebDavRequest
{
    public required HttpContext Context { get; init; }
    public required WebDavSession Session { get; init; }
    public required string Path { get; init; }
    public IfHeader? If { get; init; }

    public IFileSystem FileSystem => Session.FileSystem;

    /// <summary>The lock namespace: the user.</summary>
    public string Owner => Session.User.Username;

    public HttpRequest Request => Context.Request;
    public HttpResponse Response => Context.Response;
    public CancellationToken Aborted => Context.RequestAborted;

    public IReadOnlyCollection<string> SubmittedTokens => (If?.SubmittedTokens ?? []).ToHashSet(StringComparer.Ordinal);
}

/// <summary>
/// The WebDAV server (RFC 4918, class 1 and 2) over the user's decorated <see cref="IFileSystem"/>: OPTIONS, PROPFIND
/// (depth 0 and 1), PROPPATCH (the modification time), GET and HEAD (with ranges and conditions), PUT (streamed), DELETE,
/// MKCOL, COPY, MOVE, LOCK and UNLOCK. Permissions, quotas, events and the connection registry come from the file system
/// chain, not from here. Every storage error is a <see cref="FileSystemException"/>, mapped to a status code.
/// </summary>
internal sealed partial class WebDavHandler
{
    public const string AllowedMethods = "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK";

    private const int BufferSize = 81920;

    private readonly WebDavAuthenticator _authenticator;
    private readonly WebDavLockManager _locks;
    private readonly WebDavOptions _options;
    private readonly WebDavPaths _paths;
    private readonly ILogger _logger;
    private readonly FileExtensionContentTypeProvider _contentTypes = new();

    public WebDavHandler(WebDavAuthenticator authenticator, WebDavLockManager locks, IOptions<WebDavOptions> options, ILogger<WebDavHandler> logger)
    {
        _authenticator = authenticator;
        _locks = locks;
        _options = options.Value;
        _paths = new WebDavPaths(_options.NormalizedPath);
        _logger = logger;
    }

    internal WebDavPaths Paths => _paths;

    public async Task HandleAsync(HttpContext context)
    {
        if (!_paths.IsUnderPrefix(context.Request.Path))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var session = await _authenticator.AuthenticateAsync(context);
        if (session == null)
            return;

        var path = _paths.FromRequest(context.Request);
        if (path == null)
        {
            await WriteTextAsync(context.Response, StatusCodes.Status403Forbidden, "The path is not valid.");
            return;
        }

        IfHeader? ifHeader;
        try
        {
            ifHeader = IfHeader.Parse(context.Request.Headers["If"].ToString());
        }
        catch (FormatException ex)
        {
            await WriteTextAsync(context.Response, StatusCodes.Status400BadRequest, ex.Message);
            return;
        }

        var request = new WebDavRequest { Context = context, Session = session, Path = path, If = ifHeader };
        try
        {
            if (ifHeader != null && !await EvaluateIfAsync(request))
            {
                context.Response.StatusCode = StatusCodes.Status412PreconditionFailed;
                return;
            }
            await DispatchAsync(request);
        }
        catch (FileSystemException ex)
        {
            await WriteErrorAsync(request, ex, MapError(ex.Error));
        }
        catch (XmlException ex)
        {
            if (!context.Response.HasStarted)
                await WriteTextAsync(context.Response, StatusCodes.Status400BadRequest, "The XML body is not valid: " + ex.Message);
        }
        catch (BadHttpRequestException ex)
        {
            if (!context.Response.HasStarted)
                context.Response.StatusCode = ex.StatusCode;
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException && context.RequestAborted.IsCancellationRequested)
        {
            // The client went away (an upload that stops in the middle was aborted at the storage).
        }
    }

    private Task DispatchAsync(WebDavRequest request) => request.Request.Method.ToUpperInvariant() switch
    {
        "OPTIONS" => OptionsAsync(request),
        "GET" => GetAsync(request, withBody: true),
        "HEAD" => GetAsync(request, withBody: false),
        "PUT" => PutAsync(request),
        "DELETE" => DeleteAsync(request),
        "MKCOL" => MkcolAsync(request),
        "COPY" => CopyOrMoveAsync(request, move: false),
        "MOVE" => CopyOrMoveAsync(request, move: true),
        "PROPFIND" => PropfindAsync(request),
        "PROPPATCH" => ProppatchAsync(request),
        "LOCK" => LockAsync(request),
        "UNLOCK" => UnlockAsync(request),
        _ => MethodNotAllowedAsync(request),
    };

    private static Task MethodNotAllowedAsync(WebDavRequest request)
    {
        request.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
        request.Response.Headers.Allow = AllowedMethods;
        return Task.CompletedTask;
    }

    private static Task OptionsAsync(WebDavRequest request)
    {
        var headers = request.Response.Headers;
        headers["DAV"] = "1, 2";
        headers["MS-Author-Via"] = "DAV";
        headers.Allow = AllowedMethods;
        headers.AcceptRanges = "bytes";
        request.Response.StatusCode = StatusCodes.Status200OK;
        request.Response.ContentLength = 0;
        return Task.CompletedTask;
    }

    // ---- GET and HEAD ----

    private async Task GetAsync(WebDavRequest request, bool withBody)
    {
        var entry = await request.FileSystem.StatAsync(request.Path, followLinks: true, request.Aborted);
        if (entry == null)
        {
            request.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        if (entry.IsDirectory)
        {
            await WriteListingAsync(request, withBody);
            return;
        }

        var etag = WebDavXml.ETagOf(entry);
        var headers = request.Response.Headers;
        headers.ETag = etag;
        headers.LastModified = WebDavXml.HttpDate(entry.LastWriteTimeUtc);
        headers.AcceptRanges = "bytes";
        var precondition = CheckConditions(request.Request, entry, etag, isRead: true);
        if (precondition != 0)
        {
            request.Response.StatusCode = precondition;
            return;
        }

        request.Response.ContentType = ContentTypeOf(request.Path);
        var (start, length, rangeStatus) = ParseRange(request.Request, entry, etag);
        if (rangeStatus == StatusCodes.Status416RangeNotSatisfiable)
        {
            request.Response.StatusCode = rangeStatus;
            headers.ContentRange = $"bytes */{entry.Size}";
            return;
        }
        if (rangeStatus == StatusCodes.Status206PartialContent)
            headers.ContentRange = $"bytes {start}-{start + length - 1}/{entry.Size}";
        request.Response.StatusCode = rangeStatus;
        request.Response.ContentLength = length;
        if (!withBody)
            return;

        await using var handle = await request.FileSystem.OpenAsync(request.Path, FileOpenFlags.Read, null, request.Aborted);
        var buffer = new byte[BufferSize];
        var offset = start;
        var end = start + length;
        while (offset < end)
        {
            var read = await handle.ReadAsync(offset, buffer.AsMemory(0, (int)Math.Min(buffer.Length, end - offset)), request.Aborted);
            if (read == 0)
                break; // the file got shorter since the stat
            await request.Response.Body.WriteAsync(buffer.AsMemory(0, read), request.Aborted);
            offset += read;
        }
    }

    /// <summary>A small HTML page with the entries of a collection, for a browser.</summary>
    private async Task WriteListingAsync(WebDavRequest request, bool withBody)
    {
        var entries = new List<FileSystemEntry>();
        await foreach (var child in request.FileSystem.ListAsync(request.Path, request.Aborted))
            entries.Add(child);
        var html = new System.Text.StringBuilder();
        var title = WebUtility.HtmlEncode(request.Path);
        html.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>").Append(title).Append("</title></head><body><h1>")
            .Append(title).Append("</h1><ul>");
        foreach (var child in entries.OrderBy(e => !e.IsDirectory).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
        {
            var href = _paths.ToHref(VirtualPath.Combine(request.Path, child.Name), child.IsDirectory);
            html.Append("<li><a href=\"").Append(WebUtility.HtmlEncode(href)).Append("\">").Append(WebUtility.HtmlEncode(child.Name))
                .Append(child.IsDirectory ? "/" : "").Append("</a></li>");
        }
        html.Append("</ul></body></html>");
        var bytes = System.Text.Encoding.UTF8.GetBytes(html.ToString());
        request.Response.StatusCode = StatusCodes.Status200OK;
        request.Response.ContentType = "text/html; charset=utf-8";
        request.Response.ContentLength = bytes.Length;
        if (withBody)
            await request.Response.Body.WriteAsync(bytes, request.Aborted);
    }

    /// <summary>
    /// The conditional headers of RFC 9110 section 13: returns 0 when the request may go on, otherwise 304 (a read whose
    /// copy is current) or 412.
    /// </summary>
    internal static int CheckConditions(HttpRequest request, FileSystemEntry? entry, string? etag, bool isRead)
    {
        var headers = request.Headers;
        var ifMatch = headers.IfMatch.ToString();
        if (ifMatch.Length > 0)
        {
            if (entry == null || !(ifMatch.Trim() == "*" || ETagListContains(ifMatch, etag!, weak: false)))
                return StatusCodes.Status412PreconditionFailed;
        }
        else if (entry != null && DateTimeOffset.TryParse(headers.IfUnmodifiedSince.ToString(), out var unmodifiedSince)
            && Truncate(entry.LastWriteTimeUtc) > unmodifiedSince.UtcDateTime)
            return StatusCodes.Status412PreconditionFailed;

        var ifNoneMatch = headers.IfNoneMatch.ToString();
        if (ifNoneMatch.Length > 0)
        {
            if (entry != null && (ifNoneMatch.Trim() == "*" || ETagListContains(ifNoneMatch, etag!, weak: true)))
                return isRead ? StatusCodes.Status304NotModified : StatusCodes.Status412PreconditionFailed;
        }
        else if (isRead && entry != null && DateTimeOffset.TryParse(headers.IfModifiedSince.ToString(), out var modifiedSince)
            && Truncate(entry.LastWriteTimeUtc) <= modifiedSince.UtcDateTime)
            return StatusCodes.Status304NotModified;
        return 0;
    }

    private static DateTime Truncate(DateTime utc) => new(utc.Ticks - utc.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);

    private static bool ETagListContains(string list, string etag, bool weak)
    {
        var target = weak && etag.StartsWith("W/", StringComparison.Ordinal) ? etag[2..] : etag;
        foreach (var part in list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var candidate = part;
            if (candidate.StartsWith("W/", StringComparison.Ordinal))
            {
                if (!weak)
                    continue;
                candidate = candidate[2..];
            }
            if (candidate == target)
                return true;
        }
        return false;
    }

    /// <summary>One byte range (RFC 9110 section 14): the start, the length and 200, 206 or 416. Several ranges get the whole file.</summary>
    internal static (long Start, long Length, int Status) ParseRange(HttpRequest request, FileSystemEntry entry, string etag)
    {
        var size = entry.Size;
        var range = request.Headers.Range.ToString();
        if (!range.StartsWith("bytes=", StringComparison.OrdinalIgnoreCase) || range.Contains(','))
            return (0, size, StatusCodes.Status200OK);

        var ifRange = request.Headers.IfRange.ToString();
        if (ifRange.Length > 0)
        {
            var current = ifRange.StartsWith('"') || ifRange.StartsWith("W/", StringComparison.Ordinal)
                ? ifRange == etag
                : DateTimeOffset.TryParse(ifRange, out var date) && Truncate(entry.LastWriteTimeUtc) <= date.UtcDateTime;
            if (!current)
                return (0, size, StatusCodes.Status200OK);
        }

        var spec = range[6..].Trim();
        var dash = spec.IndexOf('-');
        if (dash < 0)
            return (0, size, StatusCodes.Status200OK);
        var first = spec[..dash].Trim();
        var last = spec[(dash + 1)..].Trim();
        if (first.Length == 0)
        {
            if (!long.TryParse(last, out var suffix) || suffix <= 0)
                return (0, size, StatusCodes.Status416RangeNotSatisfiable);
            var length = Math.Min(suffix, size);
            return size == 0 ? (0, 0, StatusCodes.Status416RangeNotSatisfiable) : (size - length, length, StatusCodes.Status206PartialContent);
        }
        if (!long.TryParse(first, out var start) || start < 0)
            return (0, size, StatusCodes.Status200OK);
        if (start >= size)
            return (0, size, StatusCodes.Status416RangeNotSatisfiable);
        var end = size - 1;
        if (last.Length > 0)
        {
            if (!long.TryParse(last, out end) || end < start)
                return (0, size, StatusCodes.Status200OK);
            end = Math.Min(end, size - 1);
        }
        return (start, end - start + 1, StatusCodes.Status206PartialContent);
    }

    private string ContentTypeOf(string path) =>
        _contentTypes.TryGetContentType(path, out var type) ? type : "application/octet-stream";

    // ---- PUT ----

    private async Task PutAsync(WebDavRequest request)
    {
        if (request.Path == VirtualPath.Root)
        {
            request.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            return;
        }
        if (request.Request.Headers.ContentRange.Count > 0)
        {
            // RFC 9110 section 14.5: a partial PUT is refused, so a client does not replace a file with a part of it.
            await WriteTextAsync(request.Response, StatusCodes.Status400BadRequest, "A PUT with Content-Range is not supported.");
            return;
        }

        var fs = request.FileSystem;
        var entry = await fs.StatAsync(request.Path, followLinks: true, request.Aborted);
        if (entry is { IsDirectory: true })
        {
            request.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            return;
        }
        var parent = await fs.StatAsync(VirtualPath.GetParent(request.Path), followLinks: true, request.Aborted);
        if (parent is not { IsDirectory: true })
        {
            request.Response.StatusCode = StatusCodes.Status409Conflict;
            return;
        }
        var precondition = CheckConditions(request.Request, entry, entry == null ? null : WebDavXml.ETagOf(entry), isRead: false);
        if (precondition != 0)
        {
            request.Response.StatusCode = precondition;
            return;
        }
        if (!await CheckLocksAsync(request, request.Path, recursive: false, parentMembership: entry == null))
            return;

        var bodySize = request.Context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (bodySize is { IsReadOnly: false })
            bodySize.MaxRequestBodySize = _options.MaxUploadBytes;

        var handle = await fs.OpenAsync(request.Path, FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate, null, request.Aborted);
        try
        {
            var buffer = new byte[BufferSize];
            long offset = 0;
            int read;
            while ((read = await request.Request.Body.ReadAsync(buffer, request.Aborted)) > 0)
            {
                await handle.WriteAsync(offset, buffer.AsMemory(0, read), request.Aborted);
                offset += read;
            }
        }
        catch
        {
            // The upload is not complete: an object store drops it, a disk keeps what arrived.
            await handle.AbortAsync();
            throw;
        }
        await handle.DisposeAsync();

        if (await fs.StatAsync(request.Path, followLinks: true, request.Aborted) is { } written)
            request.Response.Headers.ETag = WebDavXml.ETagOf(written);
        request.Response.StatusCode = entry == null ? StatusCodes.Status201Created : StatusCodes.Status204NoContent;
    }

    // ---- DELETE ----

    private async Task DeleteAsync(WebDavRequest request)
    {
        var entry = await request.FileSystem.StatAsync(request.Path, followLinks: false, request.Aborted);
        if (entry == null)
        {
            request.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        if (request.Path == VirtualPath.Root)
        {
            request.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }
        var depth = request.Request.Headers["Depth"].ToString();
        if (entry.IsDirectory && depth.Length > 0 && !depth.Equals("infinity", StringComparison.OrdinalIgnoreCase))
        {
            request.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        if (!await CheckLocksAsync(request, request.Path, recursive: true, parentMembership: true))
            return;

        var failure = await DeleteTreeAsync(request.FileSystem, request.Path, entry, request.Aborted);
        if (failure != null)
        {
            await WriteMemberFailureAsync(request, failure.Value);
            return;
        }
        _locks.RemoveWithin(request.Owner, request.Path);
        request.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    /// <summary>
    /// Removes a file, or a directory with all its members (the members first). Returns the first failure: the path and
    /// its error (a failure of the top path is thrown).
    /// </summary>
    private static async Task<(string Path, FileSystemException Error)?> DeleteTreeAsync(IFileSystem fs, string path, FileSystemEntry entry, CancellationToken ct)
    {
        if (!entry.IsDirectory)
        {
            await fs.DeleteFileAsync(path, ct);
            return null;
        }
        var children = new List<FileSystemEntry>();
        await foreach (var child in fs.ListAsync(path, ct))
            children.Add(child);
        foreach (var child in children)
        {
            var childPath = VirtualPath.Combine(path, child.Name);
            try
            {
                var failure = await DeleteTreeAsync(fs, childPath, child, ct);
                if (failure != null)
                    return failure;
            }
            catch (FileSystemException ex)
            {
                return (childPath, ex);
            }
        }
        await fs.DeleteDirectoryAsync(path, ct);
        return null;
    }

    // ---- MKCOL ----

    private async Task MkcolAsync(WebDavRequest request)
    {
        if (request.Request.ContentLength > 0 || request.Request.Headers.TransferEncoding.Count > 0)
        {
            request.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
            return;
        }
        var fs = request.FileSystem;
        if (await fs.StatAsync(request.Path, followLinks: false, request.Aborted) != null)
        {
            request.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            return;
        }
        if (await fs.StatAsync(VirtualPath.GetParent(request.Path), followLinks: true, request.Aborted) is not { IsDirectory: true })
        {
            request.Response.StatusCode = StatusCodes.Status409Conflict;
            return;
        }
        if (!await CheckLocksAsync(request, request.Path, recursive: false, parentMembership: true))
            return;
        await fs.CreateDirectoryAsync(request.Path, request.Aborted);
        request.Response.StatusCode = StatusCodes.Status201Created;
    }

    // ---- COPY and MOVE ----

    private async Task CopyOrMoveAsync(WebDavRequest request, bool move)
    {
        var fs = request.FileSystem;
        var destination = _paths.FromDestination(request.Request.Headers["Destination"].ToString(), request.Request, out var otherServer);
        if (destination == null)
        {
            request.Response.StatusCode = otherServer ? StatusCodes.Status502BadGateway : StatusCodes.Status400BadRequest;
            return;
        }
        var source = await fs.StatAsync(request.Path, followLinks: false, request.Aborted);
        if (source == null)
        {
            request.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        if (destination == request.Path || destination == VirtualPath.Root || (move && request.Path == VirtualPath.Root)
            || WebDavLockManager.IsSameOrUnder(destination, request.Path) || WebDavLockManager.IsSameOrUnder(request.Path, destination))
        {
            // Onto itself, into itself, or onto a parent of itself.
            request.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        var depth = request.Request.Headers["Depth"].ToString();
        var infinite = depth.Length == 0 || depth.Equals("infinity", StringComparison.OrdinalIgnoreCase);
        if (source.IsDirectory && !infinite && (move || depth != "0"))
        {
            request.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var overwriteHeader = request.Request.Headers["Overwrite"].ToString().Trim();
        if (overwriteHeader.Length > 0 && overwriteHeader is not ("T" or "F" or "t" or "f"))
        {
            request.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var overwrite = !overwriteHeader.Equals("F", StringComparison.OrdinalIgnoreCase);

        if (await fs.StatAsync(VirtualPath.GetParent(destination), followLinks: true, request.Aborted) is not { IsDirectory: true })
        {
            request.Response.StatusCode = StatusCodes.Status409Conflict;
            return;
        }
        var target = await fs.StatAsync(destination, followLinks: false, request.Aborted);
        if (target != null && !overwrite)
        {
            request.Response.StatusCode = StatusCodes.Status412PreconditionFailed;
            return;
        }

        if (move && !await CheckLocksAsync(request, request.Path, recursive: true, parentMembership: true))
            return;
        if (!await CheckLocksAsync(request, destination, recursive: target != null, parentMembership: true))
            return;

        try
        {
            // A file onto a file is replaced by the rename itself (atomic where the storage can); anything else is removed first.
            var replaceByRename = move && target != null && !target.IsDirectory && !source.IsDirectory;
            if (target != null && !replaceByRename)
            {
                var failure = await DeleteTreeAsync(fs, destination, target, request.Aborted);
                if (failure != null)
                {
                    await WriteMemberFailureAsync(request, failure.Value);
                    return;
                }
                _locks.RemoveWithin(request.Owner, destination);
            }

            if (move)
            {
                await fs.RenameAsync(request.Path, destination, replaceByRename ? RenameFlags.ReplaceExisting : RenameFlags.None, request.Aborted);
                _locks.RemoveWithin(request.Owner, request.Path);
                _locks.RemoveWithin(request.Owner, destination);
            }
            else
            {
                var failure = await CopyTreeAsync(fs, request.Path, source, destination, infinite, request.Aborted);
                if (failure != null)
                {
                    await WriteMemberFailureAsync(request, failure.Value);
                    return;
                }
            }
        }
        catch (FileSystemException ex) when (ex.Error == FileSystemError.OpNotSupported)
        {
            // RFC 4918 section 9.9.4 (MOVE) and 9.8.8 (COPY): the destination cannot take it, for example another storage.
            await WriteErrorAsync(request, ex, StatusCodes.Status502BadGateway);
            return;
        }

        request.Response.StatusCode = target == null ? StatusCodes.Status201Created : StatusCodes.Status204NoContent;
    }

    /// <summary>Copies a file, or a directory (with its members for depth infinity). Returns the first failure of a member.</summary>
    private static async Task<(string Path, FileSystemException Error)?> CopyTreeAsync(IFileSystem fs, string source, FileSystemEntry entry,
        string destination, bool infinite, CancellationToken ct)
    {
        if (!entry.IsDirectory)
        {
            await CopyFileAsync(fs, source, destination, ct);
            return null;
        }
        await fs.CreateDirectoryAsync(destination, ct);
        if (!infinite)
            return null;
        var children = new List<FileSystemEntry>();
        await foreach (var child in fs.ListAsync(source, ct))
            children.Add(child);
        foreach (var child in children)
        {
            var childTarget = VirtualPath.Combine(destination, child.Name);
            try
            {
                var failure = await CopyTreeAsync(fs, VirtualPath.Combine(source, child.Name), child, childTarget, infinite, ct);
                if (failure != null)
                    return failure;
            }
            catch (FileSystemException ex)
            {
                return (childTarget, ex);
            }
        }
        return null;
    }

    /// <summary>Copies the data of a file through the server, in order, so it works on every storage (also without random writes).</summary>
    private static async Task CopyFileAsync(IFileSystem fs, string source, string destination, CancellationToken ct)
    {
        await using var input = await fs.OpenAsync(source, FileOpenFlags.Read, null, ct);
        var output = await fs.OpenAsync(destination, FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate, null, ct);
        try
        {
            var buffer = new byte[BufferSize];
            long offset = 0;
            int read;
            while ((read = await input.ReadAsync(offset, buffer, ct)) > 0)
            {
                await output.WriteAsync(offset, buffer.AsMemory(0, read), ct);
                offset += read;
            }
        }
        catch
        {
            await output.AbortAsync();
            throw;
        }
        await output.DisposeAsync();
    }

    // ---- Locks and conditions ----

    /// <summary>
    /// True when the client may change <paramref name="path"/>: it submitted (in the If header) the token of every lock
    /// on the path, on its members (<paramref name="recursive"/>) and on its parent collection (<paramref name="parentMembership"/>,
    /// for a new or removed member). Otherwise writes 423 Locked and returns false.
    /// </summary>
    private async Task<bool> CheckLocksAsync(WebDavRequest request, string path, bool recursive, bool parentMembership)
    {
        var locks = _locks.Covering(request.Owner, path).AsEnumerable();
        if (recursive)
            locks = locks.Concat(_locks.Within(request.Owner, path));
        if (parentMembership && path != VirtualPath.Root)
            locks = locks.Concat(_locks.Covering(request.Owner, VirtualPath.GetParent(path)));
        var submitted = request.SubmittedTokens;
        var missing = locks.FirstOrDefault(l => !submitted.Contains(l.Token));
        if (missing == null)
            return true;
        await WebDavXml.WriteAsync(request.Response, StatusCodes.Status423Locked,
            WebDavXml.Root("error", new System.Xml.Linq.XElement(WebDavXml.Dav + "lock-token-submitted",
                new System.Xml.Linq.XElement(WebDavXml.Dav + "href", _paths.ToHref(missing.Root, missing.Root == VirtualPath.Root)))));
        return false;
    }

    /// <summary>Evaluates the If header against the resources it names (their entity tags and lock tokens).</summary>
    private async Task<bool> EvaluateIfAsync(WebDavRequest request)
    {
        var states = new Dictionary<string, (string? ETag, IReadOnlyCollection<string> Tokens)?>(StringComparer.Ordinal);
        foreach (var tag in request.If!.Lists.Select(l => l.ResourceTag).Distinct())
        {
            var path = tag == null ? request.Path : _paths.FromDestination(tag, request.Request, out _);
            if (path == null)
            {
                states[tag ?? ""] = null;
                continue;
            }
            var entry = await request.FileSystem.StatAsync(path, followLinks: true, request.Aborted);
            var tokens = _locks.Covering(request.Owner, path).Select(l => l.Token).ToList();
            states[tag ?? ""] = (entry == null ? null : WebDavXml.ETagOf(entry), tokens);
        }
        return request.If.Evaluate(tag => states[tag ?? ""]);
    }

    // ---- Errors ----

    /// <summary>The HTTP status of a storage error.</summary>
    internal static int MapError(FileSystemError error) => error switch
    {
        FileSystemError.NoSuchFile => StatusCodes.Status404NotFound,
        FileSystemError.PermissionDenied => StatusCodes.Status403Forbidden,
        FileSystemError.NotADirectory => StatusCodes.Status409Conflict,
        FileSystemError.IsADirectory => StatusCodes.Status405MethodNotAllowed,
        FileSystemError.DirectoryNotEmpty => StatusCodes.Status409Conflict,
        FileSystemError.AlreadyExists => StatusCodes.Status405MethodNotAllowed,
        FileSystemError.OpNotSupported => StatusCodes.Status501NotImplemented,
        FileSystemError.QuotaExceeded => StatusCodes.Status507InsufficientStorage,
        FileSystemError.InvalidPath => StatusCodes.Status400BadRequest,
        _ => StatusCodes.Status500InternalServerError,
    };

    private async Task WriteErrorAsync(WebDavRequest request, FileSystemException ex, int status)
    {
        if (status >= 500 && status != StatusCodes.Status502BadGateway && status != StatusCodes.Status507InsufficientStorage)
            _logger.LogWarning(ex, "WebDAV {Method} {Path} of {Username} failed.", LogText.Clean(request.Request.Method), LogText.Clean(request.Path),
                LogText.Clean(request.Owner));
        if (request.Response.HasStarted)
            return; // a GET that failed in the middle of the body: the connection ends without the rest
        request.Response.Headers.Remove("ETag");
        request.Response.Headers.Remove("Content-Range");
        request.Response.ContentLength = null;
        await WriteTextAsync(request.Response, status, ex.ClientMessage ?? WebDavXml.ReasonPhrase(status));
    }

    /// <summary>A multistatus for the failure of one member of a DELETE, COPY or MOVE of a collection.</summary>
    private async Task WriteMemberFailureAsync(WebDavRequest request, (string Path, FileSystemException Error) failure)
    {
        var status = MapError(failure.Error.Error);
        await WebDavXml.WriteAsync(request.Response, StatusCodes.Status207MultiStatus, WebDavXml.Root("multistatus",
            new System.Xml.Linq.XElement(WebDavXml.Dav + "response",
                new System.Xml.Linq.XElement(WebDavXml.Dav + "href", _paths.ToHref(failure.Path, false)),
                new System.Xml.Linq.XElement(WebDavXml.Dav + "status", WebDavXml.Status(status)))));
    }

    private static async Task WriteTextAsync(HttpResponse response, int status, string text)
    {
        response.StatusCode = status;
        response.ContentType = "text/plain; charset=utf-8";
        await response.WriteAsync(text, response.HttpContext.RequestAborted);
    }
}
