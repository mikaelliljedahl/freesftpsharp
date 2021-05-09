using System.Diagnostics.Contracts;
using System.Net;

namespace FxSsh.Services
{
    public abstract class SshService
    {
        protected internal readonly Session _session;

        public EndPoint LocalEndpoint => _session.LocalEndpoint;
        public EndPoint RemoteEndpoint => _session.RemoteEndpoint;

        public SshService(Session session)
        {
            Contract.Requires(session != null);

            _session = session;
        }

        internal protected abstract void CloseService();
    }
}
