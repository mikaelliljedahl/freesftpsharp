using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;

namespace FxSsh.SshServerModule.Security
{
    /// <summary>
    /// The login state of one SSH session (issues #58 and #63): which methods a user may try now, and which steps of a
    /// multi-step login are done. The SSH user authentication requests of a session come one after the other, so the
    /// class needs no lock.
    /// <para>
    /// The steps are the <see cref="User.RequireAllOf"/> of the user. A user with a TOTP second factor (<c>totp</c>) needs
    /// a keyboard-interactive step for the verification code after them: after any one allowed method when there is no
    /// multi-step login, or after the last step. A keyboard-interactive step asks for the code when the user has TOTP,
    /// otherwise for the password (<see cref="KeyboardInteractiveAsksForCode"/>).
    /// </para>
    /// <para>
    /// The done steps belong to one user. A request for another user name, or a change of the user's steps by the
    /// admin, starts again at the first step (RFC 4252 section 5 allows the server to forget the state).
    /// </para>
    /// </summary>
    internal sealed class AuthenticationProgress
    {
        /// <summary>A step that any allowed method can be (the first factor of a TOTP user without a multi-step login).</summary>
        private const AuthMethods AnyMethod = AuthMethods.None;

        private readonly List<AuthMethods> _done = new();
        private string _username;

        /// <summary>The steps that succeeded so far, in order.</summary>
        public IReadOnlyList<AuthMethods> Completed => _done;

        /// <summary>
        /// Checks whether <paramref name="method"/> may be tried now. Returns null when it may, or the reason why not
        /// (for the log and the events; the client gets the same failure as for a wrong credential).
        /// <paramref name="allowedMethods"/> are the effective methods of the user (with its groups, issue #61); null:
        /// <see cref="User.AllowedAuthMethods"/>.
        /// </summary>
        public string Check(User user, AuthMethods method, bool totp, AuthMethods? allowedMethods = null)
        {
            ArgumentNullException.ThrowIfNull(user);
            Synchronize(user, totp);
            if (method == AuthMethods.None)
                return "the method is not supported";

            var steps = Steps(user, totp);
            if (steps.Count > 0)
            {
                if (_done.Count >= steps.Count || (steps[_done.Count] != AnyMethod && steps[_done.Count] != method))
                    return "the method is not the next step of the multi-step login";
                // The step of the verification code: keyboard-interactive is how SSH asks for it, also for a user
                // that may not log in with keyboard-interactive alone.
                if (IsCodeStep(steps, _done.Count, totp))
                    return null;
            }
            if (((allowedMethods ?? user.AllowedAuthMethods) & method) != method)
                return "the method is not allowed for the user";
            return null;
        }

        /// <summary>True when a keyboard-interactive attempt now asks for the TOTP code; false: it asks for the password.</summary>
        public bool KeyboardInteractiveAsksForCode(User user, bool totp)
        {
            Synchronize(user, totp);
            var steps = Steps(user, totp);
            return _done.Count < steps.Count && IsCodeStep(steps, _done.Count, totp);
        }

        /// <summary>True when the next successful step completes the login; false when more steps follow (partial success).</summary>
        public bool IsLastStep(User user, bool totp)
        {
            Synchronize(user, totp);
            var steps = Steps(user, totp);
            return steps.Count == 0 || _done.Count + 1 >= steps.Count;
        }

        /// <summary>Records a verified step that is not the last one (call it only after the signature or password check).</summary>
        public void CompleteStep(User user, AuthMethods method, bool totp)
        {
            Synchronize(user, totp);
            _done.Add(method);
        }

        /// <summary>
        /// The SSH method names that the failure message offers: the next step after a partial success, otherwise null
        /// (then the server's default list, the same for every user, so the list does not tell how a user logs in).
        /// </summary>
        public IReadOnlyList<string> MethodsThatCanContinue(User user, bool totp)
        {
            if (user == null)
                return null;
            Synchronize(user, totp);
            var steps = Steps(user, totp);
            return _done.Count > 0 && _done.Count < steps.Count ? new[] { AuthMethodRules.ToSshName(steps[_done.Count]) } : null;
        }

        /// <summary>Forgets the done steps (a request for an unknown user name).</summary>
        public void Reset()
        {
            _username = null;
            _done.Clear();
        }

        /// <summary>The methods of the whole login for the events, for example "publickey,password".</summary>
        public string Describe(AuthMethods lastMethod) =>
            string.Join(",", _done.Append(lastMethod).Select(AuthMethodRules.ToSshName));

        /// <summary>The steps of the login: the configured ones, and the code step of a TOTP user.</summary>
        private static IReadOnlyList<AuthMethods> Steps(User user, bool totp)
        {
            var configured = AuthMethodRules.RequiredSteps(user);
            if (!totp || configured.Contains(AuthMethods.KeyboardInteractive))
                return configured;
            return configured.Count == 0
                ? [AnyMethod, AuthMethods.KeyboardInteractive]
                : [.. configured, AuthMethods.KeyboardInteractive];
        }

        private static bool IsCodeStep(IReadOnlyList<AuthMethods> steps, int index, bool totp) =>
            totp && steps[index] == AuthMethods.KeyboardInteractive;

        private void Synchronize(User user, bool totp)
        {
            var steps = Steps(user, totp);
            var samePrefix = _done.Count <= steps.Count && _done.Select((m, i) => steps[i] == AnyMethod || steps[i] == m).All(x => x);
            if (!string.Equals(_username, user.Username, StringComparison.Ordinal) || !samePrefix)
            {
                _username = user.Username;
                _done.Clear();
            }
        }
    }
}
