using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Storage;

namespace FxSshSftpServer.Pages.Client
{
    /// <summary>
    /// The file browser of the web client (#69): the breadcrumb and the sorted list of a directory, from
    /// <see cref="ClientStorage.ListAsync"/>, with the controls that the effective permissions allow there
    /// (<see cref="ClientPermissionMap"/>). The actions (upload, new folder, rename, delete, zip) run in wwwroot/js/client.js
    /// against <see cref="ClientApi"/>, which goes through the storage decorators again.
    /// </summary>
    [Authorize(Policy = ClientAuth.UserPolicy)]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class IndexModel : PageModel
    {
        private readonly ClientStorageFactory _storage;
        private readonly WebClientOptions _options;
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(ClientStorageFactory storage, IOptions<WebClientOptions> options, ILogger<IndexModel> logger)
        {
            _storage = storage;
            _options = options.Value;
            _logger = logger;
        }

        [BindProperty(SupportsGet = true)]
        public string Path { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Sort { get; set; }

        [BindProperty(SupportsGet = true)]
        public bool Desc { get; set; }

        public string Directory { get; private set; } = VirtualPath.Root;

        public DirectoryActions Actions { get; private set; }

        public IReadOnlyList<FileSystemEntry> Entries { get; private set; } = Array.Empty<FileSystemEntry>();

        /// <summary>Why the list is not shown (no permission, missing directory), or null.</summary>
        public string ListProblem { get; private set; }

        public StorageSpace Space { get; private set; }

        public int ChunkBytes => _options.UploadChunkBytes;

        /// <summary>True when the rows have a check box (something to do with a selection).</summary>
        public bool CanSelect => Actions is { } a && (a.Download || a.Delete);

        public async Task<IActionResult> OnGetAsync()
        {
            Directory = VirtualPath.Normalize(Path);
            ClientStorage storage;
            try
            {
                storage = await _storage.CreateAsync(HttpContext, HttpContext.RequestAborted);
            }
            catch (Exception ex) when (ex is ArgumentException or KeyNotFoundException or FileSystemException)
            {
                _logger.LogError(ex, "The storage of user {Username} cannot be created for the web client.", User.Identity?.Name);
                ListProblem = "Your storage is not available. Ask the administrator.";
                Actions = new DirectoryActions(false, false, false, false, false, false, false);
                return Page();
            }
            if (storage == null)
                return Challenge(ClientAuth.Scheme);

            Actions = storage.Permissions.For(Directory);
            try
            {
                Entries = SortEntries(await storage.ListAsync(Directory, HttpContext.RequestAborted));
            }
            catch (FileSystemException ex) when (ex.Error == FileSystemError.PermissionDenied)
            {
                ListProblem = Actions.Upload ? "You may upload files to this folder, but not see its content." : "You may not see this folder.";
            }
            catch (FileSystemException ex) when (ex.Error is FileSystemError.NoSuchFile or FileSystemError.NotADirectory)
            {
                ListProblem = "This folder does not exist.";
                Actions = new DirectoryActions(false, false, false, false, false, false, false);
            }
            Space = await storage.GetSpaceAsync(Directory, HttpContext.RequestAborted);
            return Page();
        }

        /// <summary>The breadcrumb: the name and path of each directory from the root.</summary>
        public IEnumerable<(string Name, string Path)> Breadcrumb()
        {
            yield return ("Home", VirtualPath.Root);
            var current = VirtualPath.Root;
            foreach (var segment in Directory.Split('/', StringSplitOptions.RemoveEmptyEntries))
            {
                current = VirtualPath.Combine(current, segment);
                yield return (segment, current);
            }
        }

        public string PathOf(FileSystemEntry entry) => VirtualPath.Combine(Directory, entry.Name);

        /// <summary>The link of a column header: sorts by the column, the second click in the other direction.</summary>
        public string SortLink(string column) =>
            "/client?path=" + Uri.EscapeDataString(Directory) + "&sort=" + column + (CurrentSort == column && !Desc ? "&desc=true" : "");

        public string SortIcon(string column) => CurrentSort != column ? "" : Desc ? "bi-caret-down-fill" : "bi-caret-up-fill";

        private string CurrentSort => Sort is "size" or "modified" ? Sort : "name";

        private IReadOnlyList<FileSystemEntry> SortEntries(IReadOnlyList<FileSystemEntry> entries)
        {
            IOrderedEnumerable<FileSystemEntry> directoriesFirst = entries.OrderBy(e => e.IsDirectory ? 0 : 1);
            var sorted = CurrentSort switch
            {
                "size" => Desc ? directoriesFirst.ThenByDescending(e => e.Size) : directoriesFirst.ThenBy(e => e.Size),
                "modified" => Desc ? directoriesFirst.ThenByDescending(e => e.LastWriteTimeUtc) : directoriesFirst.ThenBy(e => e.LastWriteTimeUtc),
                _ => Desc ? directoriesFirst.ThenByDescending(e => e.Name, StringComparer.OrdinalIgnoreCase)
                          : directoriesFirst.ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase),
            };
            return sorted.ToList();
        }
    }
}
