using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class SessionRequestedArgs
    {
        public SessionRequestedArgs(SessionChannel channel, string command, UserAuthArgs userauthArgs)
            : this(channel, null, command, userauthArgs)
        {
        }

        public SessionRequestedArgs(SessionChannel channel, string subsystem, string command, UserAuthArgs userauthArgs)
        {
            Contract.Requires(channel != null);
            Contract.Requires(command != null);
            Contract.Requires(userauthArgs != null);

            Channel = channel;
            CommandText = command;
            AttachedUserAuthArgs = userauthArgs;
            SubSystemName = subsystem;
        }
        public System.Net.EndPoint remoteEndpoint { get; private set; }
        public SessionChannel Channel { get; private set; }
        public string CommandText { get; private set; }
        public string SubSystemName { get; private set; }
        public UserAuthArgs AttachedUserAuthArgs { get; private set; }
    }
}
