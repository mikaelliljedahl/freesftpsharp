using System.Net;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces.Admins;

namespace SshServer.Administration
{
    /// <summary>
    /// Checks a login cookie against the stored administrator: it must still exist, be enabled, have the same
    /// security stamp (<see cref="AdminClaims.Stamp"/>) and, for an HTTP request, come from an allowed address. The
    /// cookie handler calls it on every request and the Blazor circuit periodically
    /// (<c>AdminRevalidatingAuthenticationStateProvider</c> of the admin UI). The REST API checks its bearer tokens with it too.
    /// </summary>
    public sealed class AdminSessionValidator
    {
        private readonly IAdminStore _store;

        public AdminSessionValidator(IAdminStore store)
        {
            _store = store;
        }

        /// <param name="user">The principal from the cookie.</param>
        /// <param name="client">The address of the request; null for a circuit (its address was checked when it opened).</param>
        /// <param name="ct">Cancels the check.</param>
        public async Task<bool> IsValidAsync(ClaimsPrincipal user, IPAddress client, CancellationToken ct)
        {
            var name = user?.Identity?.IsAuthenticated == true ? user.Identity.Name : null;
            if (string.IsNullOrEmpty(name))
                return false;

            var admin = await _store.GetAdminAsync(name, ct);
            if (admin == null || admin.Status != AdminStatus.Enabled)
                return false;
            if (user.FindFirstValue(AdminClaims.StampClaim) != AdminClaims.Stamp(admin))
                return false;
            return client == null || AdminClaims.IsAddressAllowed(admin, client);
        }
    }
}
