using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.SshServerModule.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Net;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Shares;
using SshServer.Interfaces.Users;

namespace FxSshSftpServer.WebClient
{
    /// <summary>A share link that a request may use, with its owner as stored now.</summary>
    public sealed record ShareVisit(Share Share, User Owner, string RemoteIp);

    /// <summary>
    /// The access rules of a share link (#70), in one place for the landing page and the endpoints. A share that cannot be
    /// used is "not found" (404), whatever the reason, so the ids cannot be probed: sharing is off, the id is not
    /// well-formed or unknown, the share is expired or used up, the owner is removed, disabled, expired or may not use the
    /// web client, or the client address is refused (the global IP rules and the auto-ban, or the networks of the share).
    /// A share with a password is unlocked by a short encrypted cookie for its path (<see cref="Unlock"/>).
    /// </summary>
    public sealed class ShareAccess
    {
        public const string CookieName = ".FxSshSftpServer.Share";
        public const string Purpose = "FreeSftpSharp.Shares.Unlock.v1";
        public const string BasePath = "/shares";
        public static readonly TimeSpan UnlockLifetime = TimeSpan.FromHours(12);

        private readonly IShareStore _store;
        private readonly ISettingsRepository _repository;
        private readonly PasswordLoginService _login;
        private readonly TimeProvider _time;
        private readonly bool _clientEnabled;
        private readonly ITimeLimitedDataProtector _protector;

        public ShareAccess(IShareStore store, ISettingsRepository repository, PasswordLoginService login, TimeProvider time,
            IOptions<WebClientOptions> options, IDataProtectionProvider protection)
        {
            _store = store;
            _repository = repository;
            _login = login;
            _time = time;
            _clientEnabled = options.Value.Enabled;
            _protector = protection.CreateProtector(Purpose).ToTimeLimitedDataProtector();
        }

        /// <summary>The share settings when sharing is on (the web client on, and <see cref="ServerSettings.Shares"/> enabled), else null.</summary>
        public ShareSettings Settings => _clientEnabled && _repository.ServerSettings.Shares is { Enabled: true } settings ? settings : null;

        public bool Enabled => Settings != null;

        /// <summary>The link of a share for the host of <paramref name="request"/>.</summary>
        public static string LinkOf(HttpRequest request, string id) => $"{request.Scheme}://{request.Host}{BasePath}/{id}";

        /// <summary>True for a path of the share links (the landing pages and their endpoints).</summary>
        public static bool IsSharePath(PathString path) => path.StartsWithSegments(BasePath, StringComparison.OrdinalIgnoreCase);

        /// <summary>The share that the request may use, or null for "not found".</summary>
        public async Task<ShareVisit> FindAsync(HttpContext http, string id, CancellationToken ct)
        {
            if (!Enabled || !ShareId.IsWellFormed(id))
                return null;
            var address = CidrNotation.Normalize(http.Connection.RemoteIpAddress ?? IPAddress.Loopback); // TestServer has no address
            if (_login.CheckAddress(address) != IpFilterResult.Allowed)
                return null;
            var share = await _store.GetAsync(id, ct);
            var now = _time.GetUtcNow().UtcDateTime;
            if (share == null || !ShareRules.IsUsable(share, now))
                return null;
            var owner = _repository.GetUser(share.Username);
            if (owner == null || owner.Id != share.UserId || owner.Status != UserStatus.Enabled || UserLoginRules.IsExpired(owner, now)
                || !owner.AllowedProtocols.Allows(UserProtocols.Web))
                return null;
            if (share.AllowedIps is { Count: > 0 } allowed && !CidrNotation.Contains(CidrNotation.ParseValid(allowed), address))
                return null;
            return new ShareVisit(share, owner, address.ToString());
        }

        /// <summary>True when the share has no password, or the request has its unlock cookie.</summary>
        public bool IsUnlocked(HttpContext http, Share share)
        {
            if (!share.HasPassword)
                return true;
            if (!http.Request.Cookies.TryGetValue(CookieName, out var value) || string.IsNullOrEmpty(value))
                return false;
            try
            {
                return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(_protector.Unprotect(value)), Encoding.UTF8.GetBytes(Payload(share)));
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        /// <summary>Checks the password of the share (PBKDF2, constant time).</summary>
        public static bool VerifyPassword(Share share, string password) =>
            share.HasPassword && !string.IsNullOrEmpty(password) && PasswordHasher.Verify(password, share.PasswordHash);

        /// <summary>Sets the unlock cookie of the share: HttpOnly, only for the path of this share, for <see cref="UnlockLifetime"/>.</summary>
        public void Unlock(HttpContext http, Share share) =>
            http.Response.Cookies.Append(CookieName, _protector.Protect(Payload(share), UnlockLifetime), new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax, // the link is opened from a mail or chat: the cookie must come with that first navigation
                Secure = http.Request.IsHttps,
                Path = BasePath + "/" + share.Id,
                MaxAge = UnlockLifetime,
                IsEssential = true,
            });

        /// <summary>Counts one download or upload; false when the share is used up now.</summary>
        public Task<bool> TryUseAsync(Share share, CancellationToken ct) => _store.TryUseAsync(share.Id, _time.GetUtcNow().UtcDateTime, ct);

        // The id and a hash of the password hash: a new password (or another share) does not accept the cookie.
        private static string Payload(Share share) =>
            share.Id + "\n" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(share.PasswordHash ?? "")));

        /// <summary>The metadata of the file events of a share visit (<c>FileEvent.Metadata</c>).</summary>
        public static IReadOnlyDictionary<string, string> EventMetadata(Share share) =>
            new Dictionary<string, string>(StringComparer.Ordinal) { ["shareId"] = share.Id, ["shareName"] = share.Name };
    }
}
