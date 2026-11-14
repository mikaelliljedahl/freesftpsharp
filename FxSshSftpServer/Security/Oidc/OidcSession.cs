#nullable enable
using System;
using System.Globalization;
using System.Security.Claims;

namespace FxSshSftpServer.Security.Oidc
{
    /// <summary>
    /// The session at the identity provider of an OpenID Connect sign-in (#145): the issuer, the session id <c>sid</c> (when
    /// the provider sends one) and the subject <c>sub</c> of the id_token. A back-channel logout names a session by them.
    /// The admin login cookie keeps them as local claims (<see cref="AddTo"/>), the web client in its session store.
    /// </summary>
    public sealed record OidcSession(string Issuer, string? Sid, string? Subject)
    {
        public const string IssuerClaim = "freesftpsharp:oidc_iss";
        public const string SidClaim = "freesftpsharp:oidc_sid";
        public const string SubjectClaim = "freesftpsharp:oidc_sub";
        public const string SignedInAtClaim = "freesftpsharp:oidc_at";

        /// <summary>The session of the principal of the id_token, or null when it has no issuer or neither sid nor sub.</summary>
        public static OidcSession? FromIdToken(ClaimsPrincipal? external)
        {
            if (external == null)
                return null;
            var issuer = external.FindFirst("iss")?.Value ?? external.FindFirst("sub")?.Issuer;
            var sid = NullIfEmpty(external.FindFirst("sid")?.Value);
            var sub = NullIfEmpty(external.FindFirst("sub")?.Value);
            if (string.IsNullOrWhiteSpace(issuer) || (sid == null && sub == null))
                return null;
            return new OidcSession(issuer, sid, sub);
        }

        /// <summary>Adds the session and the time of the sign-in to the identity of the local login cookie.</summary>
        public void AddTo(ClaimsIdentity identity, DateTimeOffset signedInAt)
        {
            ArgumentNullException.ThrowIfNull(identity);
            identity.AddClaim(new Claim(IssuerClaim, Issuer));
            if (Sid != null)
                identity.AddClaim(new Claim(SidClaim, Sid));
            if (Subject != null)
                identity.AddClaim(new Claim(SubjectClaim, Subject));
            identity.AddClaim(new Claim(SignedInAtClaim, signedInAt.UtcTicks.ToString(CultureInfo.InvariantCulture)));
        }

        /// <summary>The session and the time of the sign-in of a local login cookie, or null for a cookie of another login.</summary>
        public static (OidcSession Session, DateTimeOffset SignedInAt)? FromCookie(ClaimsPrincipal? local)
        {
            var issuer = local?.FindFirst(IssuerClaim)?.Value;
            if (string.IsNullOrEmpty(issuer)
                || !long.TryParse(local!.FindFirst(SignedInAtClaim)?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var ticks))
            {
                return null;
            }
            return (new OidcSession(issuer, local.FindFirst(SidClaim)?.Value, local.FindFirst(SubjectClaim)?.Value), new DateTimeOffset(ticks, TimeSpan.Zero));
        }

        /// <summary>
        /// True when a logout of <paramref name="logout"/> ends this session: the same issuer, and the same sid when the
        /// logout has one, else the same subject.
        /// </summary>
        public bool IsEndedBy(OidcLogout logout)
        {
            ArgumentNullException.ThrowIfNull(logout);
            if (!string.Equals(Issuer, logout.Issuer, StringComparison.Ordinal))
                return false;
            if (logout.Sid != null)
                return string.Equals(Sid, logout.Sid, StringComparison.Ordinal);
            return logout.Subject != null && string.Equals(Subject, logout.Subject, StringComparison.Ordinal);
        }

        private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
    }

    /// <summary>A valid back-channel logout (#145): the issuer and the sid and/or sub of the logout token.</summary>
    public sealed record OidcLogout(string Issuer, string? Sid, string? Subject);
}
