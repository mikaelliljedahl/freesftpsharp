using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;

namespace FxSsh.SshServerModule.Security
{
    /// <summary>
    /// The login state of one SSH session (issue #58): which methods a user may try now, and which steps of a
    /// multi-step login (<see cref="User.RequireAllOf"/>) are done. The SSH user authentication requests of a session
    /// come one after the other, so the class needs no lock.
    /// <para>
    /// The done steps belong to one user. A request for another user name, or a change of the user's steps by the
    /// admin, starts again at the first step (RFC 4252 section 5 allows the server to forget the state).
    /// </para>
    /// </summary>
    internal sealed class AuthenticationProgress
    {
        private readonly List<AuthMethods> _done = new();
        private string _username;

        /// <summary>The steps that succeeded so far, in order.</summary>
        public IReadOnlyList<AuthMethods> Completed => _done;

        /// <summary>
        /// Checks whether <paramref name="method"/> may be tried now. Returns null when it may, or the reason why not
        /// (for the log and the events; the client gets the same failure as for a wrong credential).
        /// </summary>
        public string Check(User user, AuthMethods method)
        {
            ArgumentNullException.ThrowIfNull(user);
            Synchronize(user);
            if (method == AuthMethods.None)
                return "the method is not supported";
            if ((user.AllowedAuthMethods & method) != method)
                return "the method is not allowed for the user";

            var steps = AuthMethodRules.RequiredSteps(user);
            if (steps.Count > 0 && (_done.Count >= steps.Count || steps[_done.Count] != method))
                return "the method is not the next step of the multi-step login";
            return null;
        }

        /// <summary>True when the next successful step completes the login; false when more steps follow (partial success).</summary>
        public bool IsLastStep(User user)
        {
            Synchronize(user);
            var steps = AuthMethodRules.RequiredSteps(user);
            return steps.Count == 0 || _done.Count + 1 >= steps.Count;
        }

        /// <summary>Records a verified step that is not the last one (call it only after the signature or password check).</summary>
        public void CompleteStep(User user, AuthMethods method)
        {
            Synchronize(user);
            _done.Add(method);
        }

        /// <summary>
        /// The SSH method names that the failure message offers: the next step after a partial success, otherwise null
        /// (then the server's default list, the same for every user, so the list does not tell how a user logs in).
        /// </summary>
        public IReadOnlyList<string> MethodsThatCanContinue(User user)
        {
            if (user == null)
                return null;
            Synchronize(user);
            var steps = AuthMethodRules.RequiredSteps(user);
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

        private void Synchronize(User user)
        {
            var steps = AuthMethodRules.RequiredSteps(user);
            var samePrefix = _done.Count <= steps.Count && _done.Select((m, i) => steps[i] == m).All(x => x);
            if (!string.Equals(_username, user.Username, StringComparison.Ordinal) || !samePrefix)
            {
                _username = user.Username;
                _done.Clear();
            }
        }
    }
}
