using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Shares;
using SshServer.Interfaces.Storage;

namespace FxSshSftpServer.Pages.Shares
{
    /// <summary>
    /// The landing page of a share link (#70), without a login: the name of the share, the password form of a share with a
    /// password, the shared files and folders with their download links (a read share), and the upload area (an upload
    /// share; wwwroot/js/client.js against <see cref="ShareApi"/>). A share that cannot be used is 404
    /// (<see cref="ShareAccess.FindAsync"/>). The page shows only paths in the share; the endpoints check them again.
    /// </summary>
    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class IndexModel : PageModel
    {
        public const string WrongPasswordMessage = "The password is not right.";
        public const string LockedOutMessage = "Too many wrong passwords. Try again later.";

        private readonly ShareAccess _access;
        private readonly ShareSessions _sessions;
        private readonly ClientStorageFactory _storage;
        private readonly ClientLoginThrottle _throttle;
        private readonly IEventBus _events;
        private readonly TimeProvider _time;
        private readonly WebClientOptions _options;
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(ShareAccess access, ShareSessions sessions, ClientStorageFactory storage, ClientLoginThrottle throttle, IEventBus events,
            TimeProvider time, IOptions<WebClientOptions> options, ILogger<IndexModel> logger)
        {
            _access = access;
            _sessions = sessions;
            _storage = storage;
            _throttle = throttle;
            _events = events;
            _time = time;
            _options = options.Value;
            _logger = logger;
        }

        [BindProperty(SupportsGet = true)]
        public string Share { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Path { get; set; }

        [BindProperty]
        public string Password { get; set; }

        public Share Current { get; private set; }

        public bool Locked { get; private set; }

        public string ErrorMessage { get; private set; }

        /// <summary>The folder that the page shows (a read share) or uploads into (an upload share); null: the shared paths.</summary>
        public string Directory { get; private set; }

        /// <summary>The shared paths with their entries (null for a path that is not there now).</summary>
        public IReadOnlyList<(string Path, FileSystemEntry Entry)> Roots { get; private set; } = [];

        public IReadOnlyList<FileSystemEntry> Entries { get; private set; } = [];

        public string ListProblem { get; private set; }

        public bool CanRead => Current != null && ShareRules.CanRead(Current.Scope);

        public bool CanWrite => Current != null && ShareRules.CanWrite(Current.Scope);

        public int ChunkBytes => _options.UploadChunkBytes;

        public string BaseUrl => ShareAccess.BasePath + "/" + Current?.Id;

        public string PageLink(string path) => BaseUrl + (path == null ? "" : "?path=" + Uri.EscapeDataString(path));

        public string DownloadLink(string path) => BaseUrl + "/download" + (path == null ? "" : "?path=" + Uri.EscapeDataString(path));

        public async Task<IActionResult> OnGetAsync()
        {
            var visit = await _access.FindAsync(HttpContext, Share, HttpContext.RequestAborted);
            if (visit == null)
                return NotFound();
            Current = visit.Share;
            if (!_access.IsUnlocked(HttpContext, visit.Share))
            {
                Locked = true;
                return Page();
            }
            return await ShowAsync(visit);
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var visit = await _access.FindAsync(HttpContext, Share, HttpContext.RequestAborted);
            if (visit == null)
                return NotFound();
            Current = visit.Share;
            if (!visit.Share.HasPassword || _access.IsUnlocked(HttpContext, visit.Share))
                return LocalRedirect(PageLink(null));

            Locked = true;
            if (_throttle.Throttle.IsLockedOut(visit.RemoteIp))
            {
                _logger.LogWarning("The password of the share {ShareId} was refused for {Client}: locked out after too many failures.", visit.Share.Id, visit.RemoteIp);
                ErrorMessage = LockedOutMessage;
                return new PageResult { StatusCode = StatusCodes.Status429TooManyRequests };
            }
            if (!ShareAccess.VerifyPassword(visit.Share, Password))
            {
                _throttle.Throttle.RecordFailure(visit.RemoteIp);
                _logger.LogInformation("Wrong password for the share {ShareId} from {Client}.", visit.Share.Id, visit.RemoteIp);
                await _events.PublishAsync(new AuthEvent(AuthEventType.LoginFailed)
                {
                    Timestamp = _time.GetUtcNow(),
                    Username = visit.Owner.Username,
                    RemoteIp = visit.RemoteIp,
                    Protocol = ConnectionProtocols.HttpShare,
                    Method = ShareSessions.Method + ":" + visit.Share.Id,
                    Reason = "wrong share password",
                }, HttpContext.RequestAborted);
                ErrorMessage = WrongPasswordMessage;
                Password = null;
                ModelState.Remove(nameof(Password));
                return Page();
            }
            _throttle.Throttle.RecordSuccess(visit.RemoteIp);
            _access.Unlock(HttpContext, visit.Share);
            return LocalRedirect(PageLink(null));
        }

        private async Task<IActionResult> ShowAsync(ShareVisit visit)
        {
            var connection = _sessions.Touch(visit);
            ClientStorage storage;
            try
            {
                storage = await _storage.CreateForShareAsync(visit, connection, HttpContext.RequestAborted);
            }
            catch (Exception ex) when (ex is ArgumentException or KeyNotFoundException or FileSystemException)
            {
                _logger.LogError(ex, "The storage of user {Username} cannot be created for the share {ShareId}.", visit.Owner.Username, visit.Share.Id);
                ListProblem = "The shared files are not available now.";
                return Page();
            }

            var roots = new List<(string, FileSystemEntry)>();
            foreach (var root in visit.Share.Paths)
                roots.Add((root, await TryStatAsync(storage, root)));
            Roots = roots;

            if (!string.IsNullOrWhiteSpace(Path))
            {
                var directory = VirtualPath.Normalize(Path);
                if (!SharePaths.Contains(visit.Share.Paths, directory, storage.CaseInsensitivePaths)
                    || await TryStatAsync(storage, directory) is not { IsDirectory: true })
                    return NotFound();
                Directory = directory;
            }
            else if (!CanRead && roots.Count == 1 && roots[0].Item2 is { IsDirectory: true })
            {
                Directory = roots[0].Item1; // an inbox with one folder: upload there at once
            }

            if (CanRead && Directory != null)
            {
                try
                {
                    Entries = (await storage.ListAsync(Directory, HttpContext.RequestAborted))
                        .Where(e => e.Type is FileSystemEntryType.File or FileSystemEntryType.Directory).ToList();
                }
                catch (FileSystemException ex)
                {
                    ListProblem = ex.Error == FileSystemError.PermissionDenied ? "The content of this folder is not shared." : "This folder cannot be shown.";
                }
            }
            return Page();
        }

        private async Task<FileSystemEntry> TryStatAsync(ClientStorage storage, string path)
        {
            try
            {
                var entry = await storage.FileSystem.StatAsync(path, false, HttpContext.RequestAborted);
                return entry is { Type: FileSystemEntryType.File or FileSystemEntryType.Directory } ? entry : null;
            }
            catch (FileSystemException)
            {
                return null;
            }
        }

        public string ParentOf(string directory)
        {
            var parent = VirtualPath.GetParent(directory);
            return Current.Paths.Any(p => SharePaths.Contains([p], parent, false)) ? parent : null;
        }
    }
}
