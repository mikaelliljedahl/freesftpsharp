using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Storage;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The HTTP endpoints of the web client under <c>/client/api</c> (#69). Every endpoint needs the web client login
    /// (<see cref="ClientAuth.UserPolicy"/>), every request that changes something needs the antiforgery token (header
    /// <c>RequestVerificationToken</c> or the form field), and every file operation goes through
    /// <see cref="ClientStorage.FileSystem"/>: the permission, quota, event and connection decorators decide, so a
    /// crafted request gets the same answer as the page (403 for a path the user may not use).
    /// </summary>
    public static class ClientApi
    {
        private const int DownloadBlockSize = 128 * 1024;

        public static IEndpointRouteBuilder MapClientApi(this IEndpointRouteBuilder endpoints)
        {
            var api = endpoints.MapGroup(ClientAuth.ApiPath)
                .RequireAuthorization(ClientAuth.UserPolicy)
                .DisableAntiforgery() // checked by the filter below, also for the requests without a form
                .AddEndpointFilter(ValidateAntiforgeryAsync);

            api.MapGet("/list", ListAsync);
            api.MapGet("/download", DownloadAsync);
            api.MapPost("/zip", ZipAsync);
            api.MapPost("/upload/check", CheckUploadAsync);
            api.MapGet("/upload", UploadStatusAsync);
            api.MapPost("/upload", UploadAsync);
            api.MapDelete("/upload", CancelUploadAsync);
            api.MapPost("/mkdir", CreateDirectoryAsync);
            api.MapPost("/rename", RenameAsync);
            api.MapPost("/delete", DeleteAsync);
            return endpoints;
        }

        public sealed record EntryDto(string Name, string Path, bool IsDirectory, long Size, DateTime Modified);

        public sealed record ListResponse(string Path, DirectoryActions Actions, IReadOnlyList<EntryDto> Entries);

        public sealed record UploadCheckFile(string Path, long Size);

        public sealed record UploadCheckRequest(IReadOnlyList<UploadCheckFile> Files);

        public sealed record UploadCheckResult(string Path, bool Exists, string Problem);

        public sealed record PathRequest(string Path);

        public sealed record RenameRequest(string Path, string NewName);

        public sealed record DeleteRequest(IReadOnlyList<string> Paths);

        private static async ValueTask<object> ValidateAntiforgeryAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
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

        private static async Task<IResult> ListAsync(HttpContext http, string path, CancellationToken ct)
        {
            return await WithStorageAsync(http, ct, async storage =>
            {
                var directory = VirtualPath.Normalize(path);
                var entries = await storage.ListAsync(directory, ct);
                return Results.Json(new ListResponse(directory, storage.Permissions.For(directory),
                    entries.Select(e => new EntryDto(e.Name, VirtualPath.Combine(directory, e.Name), e.IsDirectory, e.Size, e.LastWriteTimeUtc)).ToList()));
            });
        }

        private static async Task<IResult> DownloadAsync(HttpContext http, string path, CancellationToken ct)
        {
            return await WithStorageAsync(http, ct, async storage =>
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
            });
        }

        private static async Task<IResult> ZipAsync(HttpContext http, CancellationToken ct)
        {
            var form = await http.Request.ReadFormAsync(ct);
            var paths = form["path"].Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => VirtualPath.Normalize(p)).Distinct().ToList();
            if (paths.Count == 0)
                return Problem(StatusCodes.Status400BadRequest, "Select at least one file or folder.");

            return await WithStorageAsync(http, ct, async storage =>
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
                // The response starts with the first byte: refuse a selection with a file that the user may not download now.
                var denied = items.FirstOrDefault(i => !i.IsDirectory && !storage.Permissions.For(VirtualPath.GetParent(i.Path)).Download);
                if (denied != null)
                    return Problem(StatusCodes.Status403Forbidden, $"Permission denied: {denied.Path}");

                var name = paths.Count == 1 ? VirtualPath.GetName(paths[0]) : "files";
                SetDownloadHeaders(http.Response, name + ".zip");
                http.Response.ContentType = "application/zip";
                var logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(ClientApi));
                await ZipStreamer.WriteAsync(storage.FileSystem, items, http.Response.Body, logger, ct);
                return Results.Empty;
            });
        }

        private static async Task<IResult> CheckUploadAsync(HttpContext http, UploadCheckRequest request, CancellationToken ct)
        {
            if (request?.Files == null || request.Files.Count == 0)
                return Problem(StatusCodes.Status400BadRequest, "No files.");
            return await WithStorageAsync(http, ct, async storage =>
            {
                var results = new List<UploadCheckResult>();
                // The files of one directory share its free space: each needs what the ones before left.
                var used = new Dictionary<string, long>(StringComparer.Ordinal);
                foreach (var file in request.Files)
                {
                    var path = VirtualPath.Normalize(file.Path);
                    var directory = VirtualPath.GetParent(path);
                    used.TryGetValue(directory, out var before);
                    var check = await storage.CheckUploadAsync(path, Math.Max(0, file.Size) + before, ct);
                    if (check.Problem == null)
                        used[directory] = before + Math.Max(0, file.Size);
                    results.Add(new UploadCheckResult(path, check.Exists, check.Problem));
                }
                return Results.Json(results);
            });
        }

        private static Task<IResult> UploadStatusAsync(HttpContext http, string path, string id)
        {
            if (ClientClaims.Session(http.User) is not { } session || !UploadSessions.IsValidId(id))
                return Task.FromResult(Problem(StatusCodes.Status400BadRequest, "The upload id is not valid."));
            var offset = http.RequestServices.GetRequiredService<UploadSessions>().GetOffset(session, id, path ?? "");
            return Task.FromResult(Results.Json(new { offset = offset ?? 0, known = offset != null }));
        }

        private static async Task<IResult> CancelUploadAsync(HttpContext http, string id)
        {
            if (ClientClaims.Session(http.User) is not { } session || !UploadSessions.IsValidId(id))
                return Problem(StatusCodes.Status400BadRequest, "The upload id is not valid.");
            await http.RequestServices.GetRequiredService<UploadSessions>().AbortAsync(session, id);
            return Results.NoContent();
        }

        private static async Task<IResult> UploadAsync(HttpContext http, string path, string id, bool? overwrite, CancellationToken ct)
        {
            if (!UploadSessions.IsValidId(id))
                return Problem(StatusCodes.Status400BadRequest, "The upload id is not valid.");
            if (!ContentRange.TryParse(http.Request.Headers.ContentRange, out var range))
                return Problem(StatusCodes.Status400BadRequest, "The chunk needs a Content-Range header: bytes first-last/total.");
            if (http.Request.ContentLength is { } length && length != range.Length)
                return Problem(StatusCodes.Status400BadRequest, "Content-Length and Content-Range do not match.");
            var uploads = http.RequestServices.GetRequiredService<UploadSessions>();

            return await WithStorageAsync(http, ct, async storage =>
            {
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
                        if (check.Exists && overwrite != true)
                            throw new FileSystemException(FileSystemError.AlreadyExists, $"The file exists: {normalized}");
                        var flags = FileOpenFlags.Write | FileOpenFlags.Create | (overwrite == true ? FileOpenFlags.Truncate : FileOpenFlags.Exclusive);
                        return await storage.FileSystem.OpenAsync(normalized, flags, null, token);
                    }, ct);
                    return Results.Json(new { offset = progress.Offset, complete = progress.Complete });
                }
                catch (UploadException ex)
                {
                    return Results.Json(new { error = ex.Message, offset = ex.Offset }, statusCode: ex.StatusCode);
                }
            });
        }

        private static async Task<IResult> CreateDirectoryAsync(HttpContext http, PathRequest request, CancellationToken ct)
        {
            return await WithStorageAsync(http, ct, async storage =>
            {
                var path = VirtualPath.Normalize(request?.Path);
                if (ClientStorage.ValidateName(VirtualPath.GetName(path)) is { } problem)
                    return Problem(StatusCodes.Status400BadRequest, problem);
                await storage.FileSystem.CreateDirectoryAsync(path, ct);
                return Results.Json(new { path });
            });
        }

        private static async Task<IResult> RenameAsync(HttpContext http, RenameRequest request, CancellationToken ct)
        {
            return await WithStorageAsync(http, ct, async storage =>
            {
                var source = VirtualPath.Normalize(request?.Path);
                if (ClientStorage.ValidateName(request?.NewName) is { } problem)
                    return Problem(StatusCodes.Status400BadRequest, problem);
                var target = VirtualPath.Combine(VirtualPath.GetParent(source), request.NewName.Trim());
                await storage.FileSystem.RenameAsync(source, target, RenameFlags.None, ct);
                return Results.Json(new { path = target });
            });
        }

        private static async Task<IResult> DeleteAsync(HttpContext http, DeleteRequest request, CancellationToken ct)
        {
            if (request?.Paths == null || request.Paths.Count == 0)
                return Problem(StatusCodes.Status400BadRequest, "Select at least one file or folder.");
            return await WithStorageAsync(http, ct, async storage =>
            {
                foreach (var raw in request.Paths)
                    await DeleteRecursiveAsync(storage.FileSystem, VirtualPath.Normalize(raw), ct);
                return Results.NoContent();
            });
        }

        /// <summary>Removes a file, or a folder with everything in it, one storage operation (and event) per entry.</summary>
        private static async Task DeleteRecursiveAsync(IFileSystem fileSystem, string path, CancellationToken ct)
        {
            var entry = await fileSystem.StatAsync(path, false, ct)
                        ?? throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");
            if (!entry.IsDirectory)
            {
                await fileSystem.DeleteFileAsync(path, ct);
                return;
            }
            var children = new List<FileSystemEntry>();
            await foreach (var child in fileSystem.ListAsync(path, ct))
                children.Add(child);
            foreach (var child in children)
                await DeleteRecursiveAsync(fileSystem, VirtualPath.Combine(path, child.Name), ct);
            await fileSystem.DeleteDirectoryAsync(path, ct);
        }

        /// <summary>Runs an operation on the storage of the user and maps the storage errors to status codes.</summary>
        private static async Task<IResult> WithStorageAsync(HttpContext http, CancellationToken ct, Func<ClientStorage, Task<IResult>> action)
        {
            ClientStorage storage;
            try
            {
                storage = await http.RequestServices.GetRequiredService<ClientStorageFactory>().CreateAsync(http, ct);
            }
            catch (Exception ex) when (ex is ArgumentException or KeyNotFoundException or FileSystemException)
            {
                http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(ClientApi))
                    .LogError(ex, "The storage of user {Username} cannot be created for the web client.", http.User.Identity?.Name);
                return Problem(StatusCodes.Status503ServiceUnavailable, "Your storage is not available. Ask the administrator.");
            }
            if (storage == null)
                return Results.Unauthorized();

            try
            {
                return await action(storage);
            }
            catch (FileSystemException ex) when (!http.Response.HasStarted)
            {
                return Problem(StatusOf(ex.Error), ex.Message);
            }
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

        private static IResult Problem(int status, string message) => Results.Json(new { error = message }, statusCode: status);

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
