using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using SshServer.Interfaces.Admins;

namespace FxSshSftpServer.Security
{
    /// <summary>
    /// The state between the two steps of an admin login with a second factor (#63): after the right password, a short
    /// cookie that is encrypted, signed and valid for <see cref="Lifetime"/> holds the administrator and its security
    /// stamp (<see cref="AdminClaims.Stamp"/>). The code step accepts it only for the same, unchanged administrator. The
    /// cookie gives no access by itself: the login cookie is issued only after a valid code.
    /// </summary>
    public sealed class PendingTwoFactorLogin
    {
        public const string CookieName = ".FxSshSftpServer.TwoFactor";
        public const string Purpose = "FreeSftpSharp.AdminLogin.TwoFactor.v1";
        public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

        private readonly ITimeLimitedDataProtector _protector;

        public PendingTwoFactorLogin(IDataProtectionProvider provider)
        {
            _protector = provider.CreateProtector(Purpose).ToTimeLimitedDataProtector();
        }

        public void Issue(HttpContext context, Admin admin)
        {
            var payload = string.Join('\n', admin.Username, AdminClaims.Stamp(admin));
            context.Response.Cookies.Append(CookieName, _protector.Protect(payload, Lifetime), Options(context));
        }

        /// <summary>The user name and stamp of the pending login, or null when there is none or it is expired or changed.</summary>
        public (string Username, string Stamp)? Read(HttpContext context)
        {
            if (!context.Request.Cookies.TryGetValue(CookieName, out var value) || string.IsNullOrEmpty(value))
                return null;
            try
            {
                var parts = _protector.Unprotect(value).Split('\n');
                return parts.Length == 2 ? (parts[0], parts[1]) : null;
            }
            catch (CryptographicException)
            {
                return null; // expired, from other keys, or changed
            }
        }

        public void Clear(HttpContext context) => context.Response.Cookies.Delete(CookieName, Options(context));

        private static CookieOptions Options(HttpContext context) => new()
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Strict,
            Secure = context.Request.IsHttps,
            Path = "/",
            MaxAge = Lifetime,
            IsEssential = true,
        };
    }
}
