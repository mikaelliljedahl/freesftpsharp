using Microsoft.Extensions.Logging;
using SshServer.Interfaces;

namespace FxSsh.SshServerModule
{
    /// <summary>
    /// The password check of the SSH login for the other protocols (the web client, #69): the same hash formats, the
    /// same upgrade of an old hash and the same time for a failure.
    /// </summary>
    public static class UserPasswordCheck
    {
        /// <summary>True when <paramref name="password"/> is the password of <paramref name="user"/>.</summary>
        public static bool Verify(User user, string password, ISettingsRepository repository, ILogger logger) =>
            UserLogics.VerifyUserPassword(user, password ?? string.Empty, repository, logger);

        /// <summary>The work of one password check, for a refused login, so the time does not tell why it was refused.</summary>
        public static void Simulate() => UserLogics.SimulatePasswordCheck();
    }
}
