using System;
using System.Collections.Generic;
using System.Text;

namespace SshServer.Interfaces
{
    public class ServerSettings
    {
        public int Id{ get; set; }
        public string ServerRsaKey { get; set; }
        /// <summary>ECDSA P-256 host key, PKCS#8 PEM. Empty in older config files; the server then makes one and saves it.</summary>
        public string ServerEcdsaKey { get; set; }
        public string ServerBanner { get; set; }

        public int ListenToPort { get; set; }

        /// <summary>
        /// The local addresses to listen on, for example "127.0.0.1" or "::1". Empty or null: all addresses, IPv4
        /// and IPv6. "::" also means all addresses (dual stack). Read when the server starts.
        /// </summary>
        public List<string> BindToAddress { get; set; }

        /// <summary>
        /// Networks (CIDR, or single addresses) that may not connect. The server closes such a connection right
        /// after accept, before the key exchange. Wins over <see cref="WhitelistedIps"/>.
        /// </summary>
        public List<string> BlacklistedIps { get; set; }

        /// <summary>Whitelist mode: when true and <see cref="WhitelistedIps"/> is not empty, only those networks may connect.</summary>
        public bool OnlyWhitelistedIps { get; set; }

        /// <summary>The networks (CIDR, or single addresses) for <see cref="OnlyWhitelistedIps"/>.</summary>
        public List<string> WhitelistedIps { get; set; }

        /// <summary>
        /// Auto-ban: failed password logins from one address within <see cref="LoginFailureWindowSeconds"/> that
        /// ban the address for <see cref="BanDurationSeconds"/>. 0 turns auto-ban off.
        /// </summary>
        public int MaxLoginAttemptsBeforeBan { get; set; } = 5;

        /// <summary>The sliding window in seconds in which failed logins are counted. 0 turns auto-ban off.</summary>
        public int LoginFailureWindowSeconds { get; set; } = 600;

        /// <summary>How long an auto-ban lasts, in seconds. 0 turns auto-ban off.</summary>
        public int BanDurationSeconds { get; set; } = 1800;

        /// <summary>When true (the default), loopback addresses (127.0.0.0/8, ::1) are never auto-banned.</summary>
        public bool ExemptLoopbackFromBan { get; set; } = true;

        public int IdleTimeout { get; set; }
        public bool EnableCommand { get; set; }
        public bool EnableDirectTcpIp { get; set; }


    }
}
