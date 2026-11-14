using System.Net;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Security;

namespace SshServer.Administration
{
    /// <summary>Checks an admin login against the stored administrators (<see cref="IAdminStore"/>).</summary>
    public sealed class AdminCredentialValidator
    {
        private readonly IAdminStore _store;

        public AdminCredentialValidator(IAdminStore store)
        {
            _store = store;
        }

        /// <summary>
        /// The administrator when the name and password are correct, the account is enabled and the client address is
        /// allowed; otherwise null. An unknown name costs the same time as a wrong password.
        /// </summary>
        public async Task<Admin> ValidateAsync(string userName, string password, IPAddress client, CancellationToken ct)
        {
            var name = userName?.Trim();
            var admin = string.IsNullOrEmpty(name) ? null : await _store.GetAdminAsync(name, ct);
            if (admin == null)
            {
                PasswordHasher.BurnEquivalentWork();
                return null;
            }

            if (!PasswordHasher.Verify(password ?? "", admin.PasswordHash))
                return null;
            if (admin.Status != AdminStatus.Enabled || !AdminClaims.IsAddressAllowed(admin, client))
                return null;
            return admin;
        }
    }
}
