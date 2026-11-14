using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.SshServerModule.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Shares;
using SshServer.Interfaces.Storage;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The public endpoints of the share links (#70) under <c>/shares/{id}</c>, without a login: <c>GET download?path=</c>
    /// (a file, or a folder or the whole share as a zip), and the chunked upload of <see cref="ClientTransfers"/>
    /// (<c>POST upload/check</c>, <c>GET|POST|DELETE upload</c>). Every request is checked by <see cref="ShareAccess"/> (404
    /// for a share that cannot be used), needs the unlock cookie of a share with a password, may use only the paths of the
    /// share (<see cref="SharePaths"/>) and goes through the storage of the owner limited to the scope
    /// (<see cref="ClientStorageFactory.CreateForShareAsync"/>). A download or an upload counts one use of the share. The
    /// rate limit per client address is in <see cref="WebClientSetup.UseWebClient"/>.
    /// </summary>
    public static class ShareApi
    {
        public static IEndpointRouteBuilder MapShareApi(this IEndpointRouteBuilder endpoints)
        {
            var api = endpoints.MapGroup(ShareAccess.BasePath + "/{share}")
                .AllowAnonymous()
                .DisableAntiforgery() // checked by the filter below, also for the requests without a form
                .AddEndpointFilter(ClientTransfers.ValidateAntiforgeryAsync);

            api.MapGet("/download", DownloadAsync);
            api.MapPost("/upload/check", CheckUploadAsync);
            api.MapGet("/upload", UploadStatusAsync);
            api.MapPost("/upload", UploadAsync);
            api.MapDelete("/upload", CancelUploadAsync);
            return endpoints;
        }

        private enum Need
        {
            Read,
            Write,
        }

        private static async Task<IResult> DownloadAsync(HttpContext http, string share, string path, CancellationToken ct)
        {
            return await WithShareAsync(http, share, Need.Read, ct, async (visit, storage) =>
            {
                var access = http.RequestServices.GetRequiredService<ShareAccess>();
                if (string.IsNullOrWhiteSpace(path))
                {
                    // The whole share as one zip.
                    if (!await access.TryUseAsync(visit.Share, ct))
                        return NotFound();
                    return await ClientTransfers.ZipAsync(http, storage, visit.Share.Paths, ZipName(visit.Share), ct);
                }

                var normalized = VirtualPath.Normalize(path);
                if (!SharePaths.Contains(visit.Share.Paths, normalized, storage.CaseInsensitivePaths))
                    return NotFound();
                // A link is never followed: it could point out of the shared folder.
                var entry = await storage.FileSystem.StatAsync(normalized, false, ct);
                if (entry == null || entry.Type is not (FileSystemEntryType.File or FileSystemEntryType.Directory))
                    return NotFound();
                if (!await access.TryUseAsync(visit.Share, ct))
                    return NotFound();
                return entry.IsDirectory
                    ? await ClientTransfers.ZipAsync(http, storage, [normalized], VirtualPath.GetName(normalized), ct)
                    : await ClientTransfers.DownloadAsync(http, storage, normalized, ct);
            });
        }

        private static async Task<IResult> CheckUploadAsync(HttpContext http, string share, ClientTransfers.UploadCheckRequest request, CancellationToken ct)
        {
            if (request?.Files == null || request.Files.Count == 0)
                return ClientTransfers.Problem(StatusCodes.Status400BadRequest, "No files.");
            return await WithShareAsync(http, share, Need.Write, ct, async (visit, storage) =>
            {
                if (request.Files.Any(f => UploadTargetProblem(visit.Share, storage, f.Path) != null))
                    return NotFound();
                return Results.Json(await ClientTransfers.CheckUploadsAsync(storage, request.Files, ct));
            });
        }

        private static Task<IResult> UploadStatusAsync(HttpContext http, string share, string path, string id, CancellationToken ct) =>
            WithShareAsync(http, share, Need.Write, ct, (_, storage) => Task.FromResult(ClientTransfers.UploadStatus(http, storage.Session, path, id)));

        private static Task<IResult> CancelUploadAsync(HttpContext http, string share, string id, CancellationToken ct) =>
            WithShareAsync(http, share, Need.Write, ct, (_, storage) => ClientTransfers.CancelUploadAsync(http, storage.Session, id));

        private static Task<IResult> UploadAsync(HttpContext http, string share, string path, string id, bool? overwrite, CancellationToken ct)
        {
            return WithShareAsync(http, share, Need.Write, ct, async (visit, storage) =>
            {
                if (UploadTargetProblem(visit.Share, storage, path) is { } problem)
                    return problem == NotInShare ? NotFound() : ClientTransfers.Problem(StatusCodes.Status400BadRequest, problem);
                var access = http.RequestServices.GetRequiredService<ShareAccess>();
                // An existing file is replaced only when the owner allowed it for the share (and has the Overwrite permission).
                return await ClientTransfers.UploadChunkAsync(http, storage, id, path, overwrite == true && visit.Share.AllowOverwrite, ct,
                    async token =>
                    {
                        if (!await access.TryUseAsync(visit.Share, token))
                            throw new UploadException(StatusCodes.Status404NotFound, "Not found.");
                    });
            });
        }

        private const string NotInShare = "not in the share";

        /// <summary>
        /// Why a file cannot be uploaded to <paramref name="path"/>: <see cref="NotInShare"/> when its folder is not in the
        /// share (or the path names a share root itself), or the problem of the file name; null when it can.
        /// </summary>
        private static string UploadTargetProblem(Share share, ClientStorage storage, string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return NotInShare;
            var normalized = VirtualPath.Normalize(path);
            var directory = VirtualPath.GetParent(normalized);
            if (!SharePaths.Contains(share.Paths, directory, storage.CaseInsensitivePaths))
                return NotInShare;
            // The name is the last segment of what the browser sent: no separator, not "." or "..".
            var raw = path.TrimEnd('/', '\\');
            var name = raw[(raw.LastIndexOfAny(['/', '\\']) + 1)..];
            return ClientStorage.ValidateName(name) ?? (name == VirtualPath.GetName(normalized) ? null : NotInShare);
        }

        /// <summary>
        /// Runs an operation of a visitor: the share must be usable (else 404), unlocked, and have the scope; then the
        /// storage of the owner for the session of the visitor.
        /// </summary>
        private static async Task<IResult> WithShareAsync(HttpContext http, string id, Need need, CancellationToken ct,
            Func<ShareVisit, ClientStorage, Task<IResult>> action)
        {
            var services = http.RequestServices;
            var access = services.GetRequiredService<ShareAccess>();
            var visit = await access.FindAsync(http, id, ct);
            if (visit == null)
                return NotFound();
            if (!access.IsUnlocked(http, visit.Share))
                return ClientTransfers.Problem(StatusCodes.Status401Unauthorized, "Enter the password of the share first.");
            if (need == Need.Read ? !ShareRules.CanRead(visit.Share.Scope) : !ShareRules.CanWrite(visit.Share.Scope))
                return ClientTransfers.Problem(StatusCodes.Status403Forbidden,
                    need == Need.Read ? "This share does not allow downloads." : "This share does not allow uploads.");

            var connection = services.GetRequiredService<ShareSessions>().Touch(visit);
            ClientStorage storage;
            try
            {
                storage = await services.GetRequiredService<ClientStorageFactory>().CreateForShareAsync(visit, connection, ct);
            }
            catch (Exception ex) when (ex is ArgumentException or KeyNotFoundException or FileSystemException)
            {
                services.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(ShareApi))
                    .LogError(ex, "The storage of user {Username} cannot be created for the share {ShareId}.", visit.Owner.Username, visit.Share.Id);
                return ClientTransfers.Problem(StatusCodes.Status503ServiceUnavailable, "The shared files are not available now.");
            }

            try
            {
                return await action(visit, storage);
            }
            catch (FileSystemException ex) when (!http.Response.HasStarted)
            {
                services.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(ShareApi))
                    .LogInformation("A request of the share {ShareId} was refused: {Reason}", visit.Share.Id, LogText.Clean(ex.Message));
                return ClientTransfers.Problem(ClientTransfers.StatusOf(ex.Error), ex.Message);
            }
        }

        /// <summary>The name of the zip of a whole share: its name without characters that a file name cannot have.</summary>
        public static string ZipName(Share share)
        {
            var name = new string(share.Name.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' or ' ' ? c : '_').ToArray()).Trim();
            return name.Length == 0 ? "share" : name;
        }

        private static IResult NotFound() => ClientTransfers.Problem(StatusCodes.Status404NotFound, "Not found.");
    }
}
