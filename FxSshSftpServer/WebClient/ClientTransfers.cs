using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Storage;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The transfers of the browser, the same for the web client (<see cref="ClientApi"/>, #69) and the share links
    /// (<see cref="ShareApi"/>, #70): a download with byte ranges, a zip of a selection, the check before an upload and one
    /// chunk of an upload. Each works on a <see cref="ClientStorage"/>, so the decorator chain of the storage (permissions,
    /// quotas, events, connection tracking) decides; the caller has checked who may use which paths.
    /// </summary>
    public static class ClientTransfers
    {
        private const int DownloadBlockSize = 128 * 1024;

        public sealed record UploadCheckFile(string Path, long Size);

        public sealed record UploadCheckRequest(IReadOnlyList<UploadCheckFile> Files);

        public sealed record UploadCheckResult(string Path, bool Exists, string Problem);

        /// <summary>
        /// The endpoint filter of the antiforgery token: a request that changes something needs it (the header
        /// <c>RequestVerificationToken</c> or the form field); every answer is <c>no-store</c>.
        /// </summary>
        public static async ValueTask<object> ValidateAntiforgeryAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        {
            var http = context.HttpContext;
            if (!HttpMethods.IsGet(http.Request.Method) && !HttpMethods.IsHead(http.Request.Method))
            {
                var antiforgery = http.RequestServices.GetRequiredService<IAntiforgery>();
                if (!await antiforgery.IsRequestValidAsync(http))
                    return Problem(StatusCodes.Status400BadRequest, "The request has no valid antiforgery token. Reload the page.");
            }
            http.Response.Headers.CacheControl = "no-store";
            return await next(context);
        }

        /// <summary>Streams a file with <c>Content-Length</c>, <c>Accept-Ranges</c> and one byte range (206).</summary>
        public static async Task<IResult> DownloadAsync(HttpContext http, ClientStorage storage, string path, CancellationToken ct)
        {
            var normalized = VirtualPath.Normalize(path);
            var entry = await storage.FileSystem.StatAsync(normalized, true, ct);
            if (entry == null)
                return Problem(StatusCodes.Status404NotFound, $"No such file: {normalized}");
            if (entry.IsDirectory)
                return Problem(StatusCodes.Status400BadRequest, "This is a folder. Download it as a zip.");

            // Opening checks the Download permission (and asks the PreDownload hooks): a refused file gives 403 here.
            var handle = await storage.FileSystem.OpenAsync(normalized, FileOpenFlags.Read, null, ct);
            await using (handle)
            {
                var size = (await handle.StatAsync(ct)).Size;
                var lastModified = new DateTimeOffset(DateTime.SpecifyKind(entry.LastWriteTimeUtc, DateTimeKind.Utc));
                var range = ByteRange.Select(http.Request.Headers.Range, http.Request.Headers.IfRange, lastModified, size);
                if (range.Unsatisfiable)
                {
                    http.Response.Headers.ContentRange = $"bytes */{size}";
                    return Results.StatusCode(StatusCodes.Status416RangeNotSatisfiable);
                }

                var response = http.Response;
                SetDownloadHeaders(response, VirtualPath.GetName(normalized));
                response.Headers.AcceptRanges = "bytes";
                response.Headers.LastModified = lastModified.ToString("R", CultureInfo.InvariantCulture);
                if (range.IsPartial)
                {
                    response.StatusCode = StatusCodes.Status206PartialContent;
                    response.Headers.ContentRange = $"bytes {range.First}-{range.Last}/{size}";
                }
                response.ContentLength = range.Length;
                await CopyAsync(handle, range.First, range.Length, response, ct);
                return Results.Empty;
            }
        }

        /// <summary>Streams the selected files and folders (normalized paths) as one zip archive, named <paramref name="name"/>.zip.</summary>
        public static async Task<IResult> ZipAsync(HttpContext http, ClientStorage storage, IReadOnlyList<string> paths, string name, CancellationToken ct)
        {
            IReadOnlyList<ZipItem> items;
            try
            {
                items = await ZipStreamer.CollectAsync(storage.FileSystem, paths, ct);
            }
            catch (InvalidOperationException ex)
            {
                return Problem(StatusCodes.Status400BadRequest, ex.Message);
            }
            // The response starts with the first byte: refuse a selection with a file that may not be downloaded now.
            var denied = items.FirstOrDefault(i => !i.IsDirectory && !storage.Permissions.For(VirtualPath.GetParent(i.Path)).Download);
            if (denied != null)
                return Problem(StatusCodes.Status403Forbidden, $"Permission denied: {denied.Path}");

            SetDownloadHeaders(http.Response, name + ".zip");
            http.Response.ContentType = "application/zip";
            var logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(ClientTransfers));
            await ZipStreamer.WriteAsync(storage.FileSystem, items, http.Response.Body, logger, ct);
            return Results.Empty;
        }

        /// <summary>The check before an upload: per file whether it exists and why it would be refused (permissions, quota).</summary>
        public static async Task<IReadOnlyList<UploadCheckResult>> CheckUploadsAsync(ClientStorage storage, IEnumerable<UploadCheckFile> files, CancellationToken ct)
        {
            var results = new List<UploadCheckResult>();
            // The files of one directory share its free space: each needs what the ones before left.
            var used = new Dictionary<string, long>(StringComparer.Ordinal);
            foreach (var file in files)
            {
                var path = VirtualPath.Normalize(file.Path);
                var directory = VirtualPath.GetParent(path);
                used.TryGetValue(directory, out var before);
                var check = await storage.CheckUploadAsync(path, Math.Max(0, file.Size) + before, ct);
                if (check.Problem == null)
                    used[directory] = before + Math.Max(0, file.Size);
                results.Add(new UploadCheckResult(path, check.Exists, check.Problem));
            }
            return results;
        }

        /// <summary>
        /// Writes one chunk of an upload (<c>Content-Range: bytes first-last/total</c>) with <see cref="UploadSessions"/>. The
        /// first chunk checks the quota and opens the file; an existing file is replaced only with <paramref name="overwrite"/>.
        /// <paramref name="beforeOpen"/> runs before the first chunk opens the file (a share counts a use there); it can
        /// refuse the upload with an <see cref="UploadException"/>.
        /// </summary>
        public static async Task<IResult> UploadChunkAsync(HttpContext http, ClientStorage storage, string id, string path, bool overwrite,
            CancellationToken ct, Func<CancellationToken, Task> beforeOpen = null)
        {
            if (!UploadSessions.IsValidId(id))
                return Problem(StatusCodes.Status400BadRequest, "The upload id is not valid.");
            if (!ContentRange.TryParse(http.Request.Headers.ContentRange, out var range))
                return Problem(StatusCodes.Status400BadRequest, "The chunk needs a Content-Range header: bytes first-last/total.");
            if (http.Request.ContentLength is { } length && length != range.Length)
                return Problem(StatusCodes.Status400BadRequest, "Content-Length and Content-Range do not match.");
            var uploads = http.RequestServices.GetRequiredService<UploadSessions>();
            var normalized = VirtualPath.Normalize(path);
            try
            {
                var progress = await uploads.WriteChunkAsync(storage.Session, id, normalized, range, http.Request.Body, async token =>
                {
                    // The first chunk: the quota is checked before anything is written, so a full quota gives a clear
                    // message at once and no partial file.
                    var check = await storage.CheckUploadAsync(normalized, range.Total, token);
                    if (check.QuotaExceeded)
                        throw new FileSystemException(FileSystemError.QuotaExceeded, check.Problem);
                    if (check.Exists && !overwrite)
                        throw new FileSystemException(FileSystemError.AlreadyExists, $"The file exists: {normalized}");
                    if (beforeOpen != null)
                        await beforeOpen(token);
                    var flags = FileOpenFlags.Write | FileOpenFlags.Create | (overwrite ? FileOpenFlags.Truncate : FileOpenFlags.Exclusive);
                    return await storage.FileSystem.OpenAsync(normalized, flags, null, token);
                }, ct);
                return Results.Json(new { offset = progress.Offset, complete = progress.Complete });
            }
            catch (UploadException ex)
            {
                return Results.Json(new { error = ex.Message, offset = ex.Offset }, statusCode: ex.StatusCode);
            }
        }

        /// <summary>The bytes the server has of an unfinished upload of the session of <paramref name="storage"/>.</summary>
        public static IResult UploadStatus(HttpContext http, Guid session, string path, string id)
        {
            if (!UploadSessions.IsValidId(id))
                return Problem(StatusCodes.Status400BadRequest, "The upload id is not valid.");
            var offset = http.RequestServices.GetRequiredService<UploadSessions>().GetOffset(session, id, path ?? "");
            return Results.Json(new { offset = offset ?? 0, known = offset != null });
        }

        /// <summary>Aborts an unfinished upload of a session.</summary>
        public static async Task<IResult> CancelUploadAsync(HttpContext http, Guid session, string id)
        {
            if (!UploadSessions.IsValidId(id))
                return Problem(StatusCodes.Status400BadRequest, "The upload id is not valid.");
            await http.RequestServices.GetRequiredService<UploadSessions>().AbortAsync(session, id);
            return Results.NoContent();
        }

        /// <summary>The HTTP status of a storage error.</summary>
        public static int StatusOf(FileSystemError error) => error switch
        {
            FileSystemError.NoSuchFile => StatusCodes.Status404NotFound,
            FileSystemError.PermissionDenied => StatusCodes.Status403Forbidden,
            FileSystemError.AlreadyExists or FileSystemError.DirectoryNotEmpty => StatusCodes.Status409Conflict,
            FileSystemError.NotADirectory or FileSystemError.IsADirectory or FileSystemError.InvalidPath => StatusCodes.Status400BadRequest,
            FileSystemError.QuotaExceeded => StatusCodes.Status507InsufficientStorage,
            FileSystemError.OpNotSupported => StatusCodes.Status501NotImplemented,
            _ => StatusCodes.Status500InternalServerError,
        };

        /// <summary>The error body of the endpoints: <c>{"error": "..."}</c>.</summary>
        public static IResult Problem(int status, string message) => Results.Json(new { error = message }, statusCode: status);

        /// <summary>
        /// A download is always an attachment of an opaque type, never shown by the browser: user files cannot run
        /// script in the origin of the client (no stored XSS), also not as a sniffed type.
        /// </summary>
        private static void SetDownloadHeaders(HttpResponse response, string fileName)
        {
            response.ContentType = "application/octet-stream";
            var disposition = new Microsoft.Net.Http.Headers.ContentDispositionHeaderValue("attachment");
            disposition.SetHttpFileName(fileName); // filename (ASCII) and filename* (UTF-8)
            response.Headers.ContentDisposition = disposition.ToString();
            response.Headers.XContentTypeOptions = "nosniff";
            response.Headers.ContentSecurityPolicy = "default-src 'none'; sandbox";
            response.Headers.CacheControl = "no-store";
        }

        private static async Task CopyAsync(IFileHandle handle, long first, long length, HttpResponse response, CancellationToken ct)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(DownloadBlockSize);
            try
            {
                var offset = first;
                var left = length;
                while (left > 0)
                {
                    var read = await handle.ReadAsync(offset, buffer.AsMemory(0, (int)Math.Min(DownloadBlockSize, left)), ct);
                    if (read == 0)
                        break; // the file got shorter; the client sees a short body
                    await response.Body.WriteAsync(buffer.AsMemory(0, read), ct);
                    offset += read;
                    left -= read;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }
}
