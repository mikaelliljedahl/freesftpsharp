using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class CommandRequestedArgs
    {
        public CommandRequestedArgs(SessionChannel channel, string type, string command, UserAuthArgs userauthArgs)
        {
            Contract.Requires(channel != null);
            Contract.Requires(command != null);
            Contract.Requires(userauthArgs != null);

            Channel = channel;
            CommandText = command;
            AttachedUserAuthArgs = userauthArgs;
            SubSystemName = type;
        }

        public SessionChannel Channel { get; private set; }
        public string CommandText { get; private set; }
        public string SubSystemName { get; private set; }
        public UserAuthArgs AttachedUserAuthArgs { get; private set; }
    }

}
