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
    /// checked again every <see cref="Interval"/>: a removed, disabled or changed administrator loses the circuit too.
    /// </summary>
    public sealed class AdminRevalidatingAuthenticationStateProvider : RevalidatingServerAuthenticationStateProvider
    {
        public static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

        private readonly AdminSessionValidator _validator;

        public AdminRevalidatingAuthenticationStateProvider(ILoggerFactory loggerFactory, AdminSessionValidator validator)
            : base(loggerFactory)
        {
            _validator = validator;
        }

        protected override TimeSpan RevalidationInterval => Interval;

        protected override Task<bool> ValidateAuthenticationStateAsync(AuthenticationState authenticationState, CancellationToken cancellationToken) =>
            _validator.IsValidAsync(authenticationState.User, client: null, cancellationToken);
    }
}
