using System.Net;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces;

namespace FxSshSftpServer.WebClient
{
    /// <summary>The result of the password step of a web client login.</summary>
    /// <param name="User">The user when the credential is right and the user may log in; otherwise null.</param>
    /// <param name="FailureReason">Why the login was refused, for the log and the audit event (never shown to the client).</param>
    /// <param name="PasswordExpired">True when the password is older than the server allows: the user must set a new one first.</param>
    public sealed record ClientCredentialResult(User User, string FailureReason, bool PasswordExpired)
    {
        public static ClientCredentialResult Refused(string reason) => new(null, reason, false);
    }

    /// <summary>
    /// The password step of a web client login (#69). It is the seam for the authentication: today
    /// <see cref="PasswordCredentialVerifier"/> checks the stored password; the provider chain of #64 and the app
    /// passwords of #71 replace it here without a change of the pages. The second factor (TOTP) is the next step of the
    /// login pages, not of this interface.
    /// </summary>
    public interface IClientCredentialVerifier
    {
        Task<ClientCredentialResult> VerifyAsync(string username, string password, IPAddress client, CancellationToken ct);
    }
}
