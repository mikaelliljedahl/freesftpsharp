using System.Collections.Generic;

namespace FxSsh.SshServerModule
{
    public class ServerSettings
    {
        public int Id{ get; set; }
        public string ServerRsaKey { get; set; }
        public int ListenToPort { get; set; }
        public string ServerRootDirectory { get; set; }
        public List<string> BindToAddress { get; set; }
        public List<string> BlacklistedIps { get; set; }
        public int MaxLoginAttemptsBeforeBan { get; set; }

        public int IdleTimeout { get; set; }
        public bool EnableCommand { get; set; }
        public bool EnableDirectTcpIp { get; set; }

        
    }
}
