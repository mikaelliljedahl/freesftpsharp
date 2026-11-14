using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using SshServer.Interfaces;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The state between the password and the code step of a web client login with a second factor (#63): a short
    /// encrypted cookie with the user, its stamp (<see cref="ClientClaims.Stamp"/>) and whether the password is expired.
    /// It gives no access: the login cookie is issued only after a valid code.
    /// </summary>
    public sealed class ClientPendingLogin
    {
        public const string CookieName = ".FxSshSftpServer.ClientTwoFactor";
        public const string Purpose = "FreeSftpSharp.WebClient.TwoFactor.v1";
        public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

        private readonly ITimeLimitedDataProtector _protector;

        public ClientPendingLogin(IDataProtectionProvider provider)
        {
            _protector = provider.CreateProtector(Purpose).ToTimeLimitedDataProtector();
        }

        public void Issue(HttpContext context, User user, bool passwordExpired)
        {
            var payload = string.Join('\n', user.Username, ClientClaims.Stamp(user), passwordExpired ? "1" : "0");
            context.Response.Cookies.Append(CookieName, _protector.Protect(payload, Lifetime), Options(context));
        }

        /// <summary>The pending login, or null when there is none or it is expired or changed.</summary>
        public (string Username, string Stamp, bool PasswordExpired)? Read(HttpContext context)
        {
            if (!context.Request.Cookies.TryGetValue(CookieName, out var value) || string.IsNullOrEmpty(value))
                return null;
            try
            {
                var parts = _protector.Unprotect(value).Split('\n');
                return parts.Length == 3 ? (parts[0], parts[1], parts[2] == "1") : null;
            }
            catch (CryptographicException)
            {
                return null;
            }
        }

        public void Clear(HttpContext context) => context.Response.Cookies.Delete(CookieName, Options(context));

        private static CookieOptions Options(HttpContext context) => new()
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Strict,
            Secure = context.Request.IsHttps,
            Path = ClientAuth.CookiePath,
            MaxAge = Lifetime,
            IsEssential = true,
        };
    }
}
