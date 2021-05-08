using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class SessionRequestedArgs
    {
        public SessionRequestedArgs(SessionChannel channel, string command, UserauthArgs userauthArgs)
            : this(channel, null, command, userauthArgs)
        {
        }

        public SessionRequestedArgs(SessionChannel channel, string subsystem, string command, UserauthArgs userauthArgs)
        {
            Contract.Requires(channel != null);
            Contract.Requires(command != null);
            Contract.Requires(userauthArgs != null);

            Channel = channel;
            CommandText = command;
            AttachedUserauthArgs = userauthArgs;
            SubSystemName = subsystem;
        }

        public SessionChannel Channel { get; private set; }
        public string CommandText { get; private set; }
        public string SubSystemName { get; private set; }
        public UserauthArgs AttachedUserauthArgs { get; private set; }
    }
}
