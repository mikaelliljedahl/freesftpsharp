using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
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
        public static IEndpointRouteBuilder MapClientApi(this IEndpointRouteBuilder endpoints)
        {
            var api = endpoints.MapGroup(ClientAuth.ApiPath)
                .RequireAuthorization(ClientAuth.UserPolicy)
                .DisableAntiforgery() // checked by the filter below, also for the requests without a form
                .AddEndpointFilter(ClientTransfers.ValidateAntiforgeryAsync);

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

        public sealed record PathRequest(string Path);

        public sealed record RenameRequest(string Path, string NewName);

        public sealed record DeleteRequest(IReadOnlyList<string> Paths);

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

        private static Task<IResult> DownloadAsync(HttpContext http, string path, CancellationToken ct) =>
            WithStorageAsync(http, ct, storage => ClientTransfers.DownloadAsync(http, storage, path, ct));

        private static async Task<IResult> ZipAsync(HttpContext http, CancellationToken ct)
        {
            var form = await http.Request.ReadFormAsync(ct);
            var paths = form["path"].Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => VirtualPath.Normalize(p)).Distinct().ToList();
            if (paths.Count == 0)
                return Problem(StatusCodes.Status400BadRequest, "Select at least one file or folder.");
            var name = paths.Count == 1 ? VirtualPath.GetName(paths[0]) : "files";
            return await WithStorageAsync(http, ct, storage => ClientTransfers.ZipAsync(http, storage, paths, name, ct));
        }

        private static async Task<IResult> CheckUploadAsync(HttpContext http, ClientTransfers.UploadCheckRequest request, CancellationToken ct)
        {
            if (request?.Files == null || request.Files.Count == 0)
                return Problem(StatusCodes.Status400BadRequest, "No files.");
            return await WithStorageAsync(http, ct, async storage => Results.Json(await ClientTransfers.CheckUploadsAsync(storage, request.Files, ct)));
        }

        private static Task<IResult> UploadStatusAsync(HttpContext http, string path, string id) =>
            Task.FromResult(ClientClaims.Session(http.User) is { } session
                ? ClientTransfers.UploadStatus(http, session, path, id)
                : Problem(StatusCodes.Status400BadRequest, "The upload id is not valid."));

        private static Task<IResult> CancelUploadAsync(HttpContext http, string id) =>
            ClientClaims.Session(http.User) is { } session
                ? ClientTransfers.CancelUploadAsync(http, session, id)
                : Task.FromResult(Problem(StatusCodes.Status400BadRequest, "The upload id is not valid."));

        private static Task<IResult> UploadAsync(HttpContext http, string path, string id, bool? overwrite, CancellationToken ct) =>
            WithStorageAsync(http, ct, storage => ClientTransfers.UploadChunkAsync(http, storage, id, path, overwrite == true, ct));

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

        private static int StatusOf(FileSystemError error) => ClientTransfers.StatusOf(error);

        private static IResult Problem(int status, string message) => ClientTransfers.Problem(status, message);
    }
}
