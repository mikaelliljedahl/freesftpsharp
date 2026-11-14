using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.Extensions.Logging;

namespace FxSshSftpServer.Security
{
    /// <summary>
    /// The authentication state of a Blazor circuit. A circuit lives long after its HTTP request, so the login is
    /// checked again every <see cref="Interval"/>: a removed, disabled or changed administrator loses the circuit too, and so
    /// does a session that the identity provider ended (back-channel logout, #145).
    /// </summary>
    public sealed class AdminRevalidatingAuthenticationStateProvider : RevalidatingServerAuthenticationStateProvider
    {
        public static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

        private readonly AdminSessionValidator _validator;
        private readonly Oidc.AdminOidcLogouts _logouts;

        /// <param name="logouts">The back-channel logouts of the provider (#145). Null: none.</param>
        public AdminRevalidatingAuthenticationStateProvider(ILoggerFactory loggerFactory, AdminSessionValidator validator, Oidc.AdminOidcLogouts logouts = null)
            : base(loggerFactory)
        {
            _validator = validator;
            _logouts = logouts;
        }

        protected override TimeSpan RevalidationInterval => Interval;

        protected override Task<bool> ValidateAuthenticationStateAsync(AuthenticationState authenticationState, CancellationToken cancellationToken) =>
            _logouts?.IsEnded(authenticationState.User) == true
                ? Task.FromResult(false)
                : _validator.IsValidAsync(authenticationState.User, client: null, cancellationToken);
    }
}
