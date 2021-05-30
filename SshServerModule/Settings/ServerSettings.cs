using LiteDB;
using System;
using System.Collections.Generic;
using System.Text;

namespace FxSsh.SshServerModule
{
    public class ServerSettings
    {
        public ObjectId Id{ get; set; }
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
