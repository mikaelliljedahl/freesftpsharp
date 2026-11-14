using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components.Authorization;
using SshServer.Interfaces.Admins;

namespace FxSshSftpServer.Security
{
    /// <summary>
    /// The administrator of the current Blazor circuit (scoped). The admin application services use it for their own
    /// checks, so a missing permission is refused on the server also when a page shows a button by mistake. It follows
    /// the authentication state: when the circuit loses its login (<see cref="AdminRevalidatingAuthenticationStateProvider"/>),
    /// the actor becomes anonymous.
    /// </summary>
    public sealed class CurrentAdmin : IDisposable
    {
        private readonly AuthenticationStateProvider _authentication;
        private Task<AuthenticationState> _state;

        public CurrentAdmin(AuthenticationStateProvider authentication)
        {
            _authentication = authentication;
            _authentication.AuthenticationStateChanged += OnChanged;
        }

        /// <summary>The actor now; anonymous when the login is not known (yet) or not valid any more.</summary>
        public AdminActor Actor
        {
            get
            {
                var state = _state;
                if (state == null)
                {
                    try
                    {
                        state = _state = _authentication.GetAuthenticationStateAsync();
                    }
                    catch (InvalidOperationException)
                    {
                        // Outside a component (no authentication state yet): fail closed.
                        return AdminActor.Anonymous;
                    }
                }
                return state.IsCompletedSuccessfully ? AdminClaims.ToActor(state.Result.User) : AdminActor.Anonymous;
            }
        }

        public bool Has(AdminPermissions permission) => Actor.Has(permission);

        private void OnChanged(Task<AuthenticationState> state) => _state = state;

        public void Dispose() => _authentication.AuthenticationStateChanged -= OnChanged;
    }
}
