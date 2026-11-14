using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Net;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Shares;
using SshServer.Interfaces.Storage;

namespace FxSshSftpServer.WebClient
{
    /// <summary>What a user enters for a new share link.</summary>
    public sealed record ShareRequest
    {
        public string Name { get; init; }
        public string Description { get; init; }
        public IReadOnlyList<string> Paths { get; init; } = [];
        public ShareScope Scope { get; init; }
        public bool AllowOverwrite { get; init; }
        public string Password { get; init; }
        public DateTime? ExpiresAt { get; init; }
        public int MaxUses { get; init; }
        public IReadOnlyList<string> AllowedIps { get; init; } = [];
    }

    /// <summary>The result of <see cref="ShareService.CreateAsync"/>: the share, or the problems for the user.</summary>
    public sealed record ShareCreateResult(Share Share, IReadOnlyList<string> Errors);

    /// <summary>
    /// The share links of the signed-in user of the web client (#70): create (with the rules of
    /// <see cref="ServerSettings.Shares"/>), list and revoke. A user sees and revokes only its own shares. The paths are
    /// checked through the storage of the user (<see cref="ClientStorage"/>): each must exist and be visible to the user, and
    /// an upload share needs folders.
    /// </summary>
    public sealed class ShareService
    {
        public const int MaxPasswordLength = 256;

        private readonly IShareStore _store;
        private readonly ShareAccess _access;
        private readonly TimeProvider _time;
        private readonly ILogger<ShareService> _logger;

        public ShareService(IShareStore store, ShareAccess access, TimeProvider time, ILogger<ShareService> logger)
        {
            _store = store;
            _access = access;
            _time = time;
            _logger = logger;
        }

        public Task<IReadOnlyList<Share>> ListAsync(User owner, CancellationToken ct) => _store.ListAsync(owner.Id, ct);

        public async Task<ShareCreateResult> CreateAsync(ClientStorage storage, ShareRequest request, CancellationToken ct)
        {
            var errors = new List<string>();
            var settings = _access.Settings;
            if (settings == null)
                return new ShareCreateResult(null, ["Sharing is turned off on this server."]);

            var name = request.Name?.Trim();
            if (string.IsNullOrEmpty(name))
                errors.Add("Enter a name.");
            else if (name.Length > ShareRules.MaxNameLength)
                errors.Add($"The name can have at most {ShareRules.MaxNameLength} characters.");
            var description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim();
            if (description?.Length > ShareRules.MaxDescriptionLength)
                errors.Add($"The description can have at most {ShareRules.MaxDescriptionLength} characters.");
            if (!Enum.IsDefined(request.Scope))
                errors.Add("Select what the share allows.");

            var paths = SharePaths.Normalize(request.Paths, errors);
            foreach (var path in paths)
            {
                FileSystemEntry entry;
                try
                {
                    entry = await storage.FileSystem.StatAsync(path, false, ct);
                }
                catch (FileSystemException)
                {
                    entry = null;
                }
                if (entry == null || entry.Type is not (FileSystemEntryType.File or FileSystemEntryType.Directory))
                    errors.Add($"{path} does not exist.");
                else if (ShareRules.CanWrite(request.Scope) && !entry.IsDirectory)
                    errors.Add($"{path} is a file: a share for uploads needs folders.");
            }

            var password = string.IsNullOrEmpty(request.Password) ? null : request.Password;
            if (password == null && settings.RequirePassword)
                errors.Add("Enter a password: every share on this server needs one.");
            if (password?.Length > MaxPasswordLength)
                errors.Add($"The password can have at most {MaxPasswordLength} characters.");

            var now = _time.GetUtcNow().UtcDateTime;
            DateTime? expires = request.ExpiresAt is { } e ? DateTime.SpecifyKind(e.Kind == DateTimeKind.Local ? e.ToUniversalTime() : e, DateTimeKind.Utc) : null;
            if (expires != null && expires <= now)
                errors.Add("The expiry must be in the future.");
            if (settings.MaxLifetimeDays > 0)
            {
                var latest = now.AddDays(settings.MaxLifetimeDays);
                if (expires == null)
                    errors.Add($"Enter an expiry: a share on this server can live at most {settings.MaxLifetimeDays} days.");
                else if (expires > latest)
                    errors.Add($"The expiry can be at most {settings.MaxLifetimeDays} days from now.");
            }
            if (request.MaxUses < 0)
                errors.Add("The maximum number of uses cannot be negative (0 is unlimited).");
            var allowedIps = (request.AllowedIps ?? []).Where(i => !string.IsNullOrWhiteSpace(i)).Select(i => i.Trim()).Distinct().ToList();
            errors.AddRange(CidrNotation.FindInvalid(allowedIps).Select(i => $"'{i}' is not an IP address or a network in CIDR notation."));

            if (errors.Count > 0)
                return new ShareCreateResult(null, errors);

            var share = new Share
            {
                Id = ShareId.New(),
                UserId = storage.User.Id,
                Username = storage.User.Username,
                Name = name,
                Description = description,
                Paths = paths,
                Scope = request.Scope,
                AllowOverwrite = ShareRules.CanWrite(request.Scope) && request.AllowOverwrite,
                PasswordHash = password == null ? null : PasswordHasher.Hash(password),
                ExpiresAt = expires,
                MaxUses = request.MaxUses,
                AllowedIps = allowedIps.Count == 0 ? null : allowedIps,
                CreatedAt = now,
            };
            await _store.AddAsync(share, ct);
            _logger.LogInformation("{Username} created the share {ShareId} ({Scope}) of {Paths}.",
                share.Username, share.Id, share.Scope, LogText.Clean(string.Join(", ", share.Paths)));
            return new ShareCreateResult(share, []);
        }

        /// <summary>Removes a share of <paramref name="owner"/>; false when it is not one of its shares.</summary>
        public async Task<bool> RevokeAsync(User owner, string id, CancellationToken ct)
        {
            if (!ShareId.IsWellFormed(id))
                return false;
            var share = await _store.GetAsync(id, ct);
            if (share == null || share.UserId != owner.Id || !await _store.RemoveAsync(id, ct))
                return false;
            _logger.LogInformation("{Username} revoked the share {ShareId}.", owner.Username, id);
            return true;
        }
    }
}
