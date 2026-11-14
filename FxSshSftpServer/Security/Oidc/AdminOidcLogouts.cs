#nullable enable
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Claims;

namespace FxSshSftpServer.Security.Oidc
{
    /// <summary>
    /// The back-channel logouts of the admin UI (#145). The admin login cookie has no session on the server: it carries the
    /// session of the provider (<see cref="OidcSession"/>) and is checked on every request and every circuit check. A
    /// logout is kept here for <see cref="Retention"/> (longer than an admin cookie lives without a request); a cookie of
    /// a session that it ends, signed in before it, is rejected. In memory and per node: with several nodes the logout
    /// reaches only the node that got it, and a restart forgets it (see docs/OIDC.md).
    /// </summary>
    public sealed class AdminOidcLogouts
    {
        public static readonly TimeSpan Retention = TimeSpan.FromHours(12);

        private const int MaximumEntries = 10_000;

        private readonly TimeProvider _time;
        private readonly ConcurrentDictionary<OidcLogout, DateTimeOffset> _logouts = new();

        public AdminOidcLogouts(TimeProvider time)
        {
            _time = time;
        }

        public void Add(OidcLogout logout)
        {
            ArgumentNullException.ThrowIfNull(logout);
            var now = _time.GetUtcNow();
            _logouts[logout] = now;
            foreach (var (old, at) in _logouts)
            {
                if (now - at > Retention)
                    _logouts.TryRemove(old, out _);
            }
            // A provider (or a forged but signed flood) cannot grow the list without bounds: the oldest go first.
            if (_logouts.Count > MaximumEntries)
            {
                foreach (var (old, _) in _logouts.OrderBy(e => e.Value).Take(_logouts.Count - MaximumEntries).ToList())
                    _logouts.TryRemove(old, out _);
            }
        }

        /// <summary>True when the login cookie <paramref name="user"/> belongs to a provider session that a logout ended.</summary>
        public bool IsEnded(ClaimsPrincipal? user)
        {
            if (_logouts.IsEmpty || OidcSession.FromCookie(user) is not { } cookie)
                return false;
            var now = _time.GetUtcNow();
            foreach (var (logout, at) in _logouts)
            {
                if (now - at <= Retention && cookie.SignedInAt <= at && cookie.Session.IsEndedBy(logout))
                    return true;
            }
            return false;
        }
    }
}
