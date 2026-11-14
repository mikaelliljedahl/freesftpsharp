using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Shares;
using SshServer.Interfaces.Storage;

namespace FxSshSftpServer.Pages.Client
{
    /// <summary>
    /// The share links of the signed-in user (#70): create one for files or folders (a download link, an upload "inbox" or
    /// both), see the own shares with their links and uses, and revoke one. Every change goes through
    /// <see cref="ShareService"/>, always for the user of the login. 404 while sharing is off.
    /// </summary>
    [Authorize(Policy = ClientAuth.UserPolicy)]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class SharesModel : PageModel
    {
        private readonly ShareService _shares;
        private readonly ShareAccess _access;
        private readonly ClientStorageFactory _storage;
        private readonly ILogger<SharesModel> _logger;

        public SharesModel(ShareService shares, ShareAccess access, ClientStorageFactory storage, ILogger<SharesModel> logger)
        {
            _shares = shares;
            _access = access;
            _storage = storage;
            _logger = logger;
        }

        [BindProperty(SupportsGet = true)]
        public string Path { get; set; }

        [BindProperty]
        public string Name { get; set; }

        [BindProperty]
        public string Description { get; set; }

        [BindProperty]
        public string PathsText { get; set; }

        [BindProperty]
        public ShareScope Scope { get; set; }

        [BindProperty]
        public bool AllowOverwrite { get; set; }

        [BindProperty]
        public string Password { get; set; }

        /// <summary>The expiry, UTC, as the browser sends a datetime-local value ("2026-12-31T23:59").</summary>
        [BindProperty]
        public string ExpiresAt { get; set; }

        [BindProperty]
        public int MaxUses { get; set; }

        [BindProperty]
        public string AllowedIpsText { get; set; }

        public ShareSettings Settings { get; private set; }

        public IReadOnlyList<Share> Shares { get; private set; } = [];

        public IReadOnlyList<string> Errors { get; private set; } = [];

        /// <summary>The link of the share that was just created.</summary>
        public string CreatedLink { get; private set; }

        public string Message { get; private set; }

        public string LinkOf(Share share) => ShareAccess.LinkOf(Request, share.Id);

        public async Task<IActionResult> OnGetAsync()
        {
            if (!Load())
                return NotFound();
            if (!string.IsNullOrWhiteSpace(Path))
            {
                var path = VirtualPath.Normalize(Path);
                PathsText = path;
                Name = VirtualPath.GetName(path);
            }
            await ListAsync();
            return Page();
        }

        public async Task<IActionResult> OnPostCreateAsync()
        {
            if (!Load())
                return NotFound();
            var storage = await _storage.CreateAsync(HttpContext, HttpContext.RequestAborted);
            if (storage == null)
                return Challenge(ClientAuth.Scheme);

            var errors = new List<string>();
            DateTime? expires = null;
            if (!string.IsNullOrWhiteSpace(ExpiresAt))
            {
                if (DateTime.TryParse(ExpiresAt, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var value))
                    expires = DateTime.SpecifyKind(value, DateTimeKind.Utc);
                else
                    errors.Add("The expiry is not a date and time.");
            }
            if (errors.Count == 0)
            {
                var result = await _shares.CreateAsync(storage, new ShareRequest
                {
                    Name = Name,
                    Description = Description,
                    Paths = Lines(PathsText),
                    Scope = Scope,
                    AllowOverwrite = AllowOverwrite,
                    Password = Password,
                    ExpiresAt = expires,
                    MaxUses = MaxUses,
                    AllowedIps = Lines(AllowedIpsText),
                }, HttpContext.RequestAborted);
                errors.AddRange(result.Errors);
                if (result.Share != null)
                {
                    CreatedLink = LinkOf(result.Share);
                    Name = Description = PathsText = ExpiresAt = AllowedIpsText = null;
                    MaxUses = 0;
                    AllowOverwrite = false;
                    ModelState.Clear();
                }
            }
            Errors = errors;
            Password = null;
            ModelState.Remove(nameof(Password));
            await ListAsync();
            return Page();
        }

        public async Task<IActionResult> OnPostRevokeAsync(string id)
        {
            if (!Load())
                return NotFound();
            var storage = await _storage.CreateAsync(HttpContext, HttpContext.RequestAborted);
            if (storage == null)
                return Challenge(ClientAuth.Scheme);
            Message = await _shares.RevokeAsync(storage.User, id, HttpContext.RequestAborted)
                ? "The share was revoked. Its link does not work any more."
                : "The share does not exist (any more).";
            await ListAsync();
            return Page();
        }

        private bool Load()
        {
            Settings = _access.Settings;
            return Settings != null;
        }

        private async Task ListAsync()
        {
            var storage = await _storage.CreateAsync(HttpContext, HttpContext.RequestAborted);
            if (storage != null)
                Shares = await _shares.ListAsync(storage.User, HttpContext.RequestAborted);
        }

        private static List<string> Lines(string text) =>
            (text ?? "").Split(['\n', '\r', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    }
}
