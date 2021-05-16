using System;
using System.Collections.Generic;
using System.Text;

namespace FxSsh.SshServerSettings
{
    public class SshServerSettings
    {
        public string ServerRsaKey { get; set; }
        public int ListenToPort { get; set; }
        public string ServerRootDirectory { get; set; }
        public List<string> BindToAddress { get; set; }
        public List<string> BlacklistedIps { get; set; }
        public int MaxLoginAttemptsBeforeBan { get; set; }

    }

    /// <summary>
        /// Either provide Password or Key for login
        /// </summary>
        /// <value></value>
    public class User
    {
        public string Username { get; set; }
        public string UserRootDirectory { get; set; }
        public string HashedPassword { get; set; }
        public string RsaKey { get; set; }
        public bool OnlyWhitelistedIps { get; set; }
        public List<string> WhitelistedIps { get; set; }
        public DateTime LastSuccessfulLogin { get; set; }
 
    }
}