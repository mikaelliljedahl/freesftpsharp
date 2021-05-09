using FxSsh.Messages.Connection;
using System.Text;

namespace FxSsh.Messages.Connection
{
    public class SubsystemRequestMessage : ChannelRequestMessage
    {
        public string SubsystemName { get; private set; }

        protected override void OnLoad(SshDataWorker reader)
        {
            /*
             byte      SSH_MSG_CHANNEL_REQUEST
             uint32    recipient channel
             string    "subsystem"
             boolean   want reply
             string    subsystem name
            */
            base.OnLoad(reader);

            SubsystemName = reader.ReadString(Encoding.ASCII);
        }
    }
}
