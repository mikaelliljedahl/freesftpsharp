using System;
using System.Collections.Generic;
using System.Text;

namespace FxSsh.SshServerLoader
{


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