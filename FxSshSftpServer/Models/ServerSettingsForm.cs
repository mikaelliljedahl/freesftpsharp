using SshServer.Interfaces;
using System.ComponentModel.DataAnnotations;

namespace FxSshSftpServer.Models
{
    /// <summary>
    /// The general server settings page. <see cref="ApplyTo"/> changes only these fields, so the host keys and the
    /// access settings of <see cref="AccessControlForm"/> stay as they are stored.
    /// </summary>
    public sealed class ServerSettingsForm
    {
        [Range(1, 65535, ErrorMessage = "The port must be a number from 1 to 65535.")]
        public int ListenToPort { get; set; }

        [IpAddressList]
        public string BindToAddress { get; set; } = "";

        [StringLength(200, ErrorMessage = "The banner can have at most 200 characters.")]
        [RegularExpression(@"^[\x20-\x7E]*$", ErrorMessage = "The banner can only have printable ASCII characters.")]
        public string ServerBanner { get; set; } = "";

        [Range(0, 86400, ErrorMessage = "The idle timeout must be from 0 to 86400 seconds.")]
        public int IdleTimeout { get; set; }

        public bool EnableCommand { get; set; }

        public bool EnableDirectTcpIp { get; set; }

        public static ServerSettingsForm From(ServerSettings settings) => new()
        {
            ListenToPort = settings.ListenToPort,
            BindToAddress = EntryList.Format(settings.BindToAddress),
            ServerBanner = settings.ServerBanner ?? "",
            IdleTimeout = settings.IdleTimeout,
            EnableCommand = settings.EnableCommand,
            EnableDirectTcpIp = settings.EnableDirectTcpIp,
        };

        public void ApplyTo(ServerSettings settings)
        {
            settings.ListenToPort = ListenToPort;
            settings.BindToAddress = EntryList.Parse(BindToAddress);
            settings.ServerBanner = string.IsNullOrWhiteSpace(ServerBanner) ? null : ServerBanner.Trim();
            settings.IdleTimeout = IdleTimeout;
            settings.EnableCommand = EnableCommand;
            settings.EnableDirectTcpIp = EnableDirectTcpIp;
        }
    }

    /// <summary>The IP access page: blacklist, whitelist mode and auto-ban. <see cref="ApplyTo"/> changes only these fields.</summary>
    public sealed class AccessControlForm
    {
        [CidrList]
        public string BlacklistedIps { get; set; } = "";

        public bool OnlyWhitelistedIps { get; set; }

        [CidrList]
        public string WhitelistedIps { get; set; } = "";

        [Range(0, 1000, ErrorMessage = "Use a number from 0 to 1000 (0 turns auto-ban off).")]
        public int MaxLoginAttemptsBeforeBan { get; set; }

        [Range(0, 31_536_000, ErrorMessage = "Use a number of seconds from 0 to 31536000 (0 turns auto-ban off).")]
        public int LoginFailureWindowSeconds { get; set; }

        [Range(0, 31_536_000, ErrorMessage = "Use a number of seconds from 0 to 31536000 (0 turns auto-ban off).")]
        public int BanDurationSeconds { get; set; }

        public bool ExemptLoopbackFromBan { get; set; }

        /// <summary>Auto-ban is on only when all three numbers are above 0.</summary>
        public bool AutoBanEnabled => MaxLoginAttemptsBeforeBan > 0 && LoginFailureWindowSeconds > 0 && BanDurationSeconds > 0;

        public static AccessControlForm From(ServerSettings settings) => new()
        {
            BlacklistedIps = EntryList.Format(settings.BlacklistedIps),
            OnlyWhitelistedIps = settings.OnlyWhitelistedIps,
            WhitelistedIps = EntryList.Format(settings.WhitelistedIps),
            MaxLoginAttemptsBeforeBan = settings.MaxLoginAttemptsBeforeBan,
            LoginFailureWindowSeconds = settings.LoginFailureWindowSeconds,
            BanDurationSeconds = settings.BanDurationSeconds,
            ExemptLoopbackFromBan = settings.ExemptLoopbackFromBan,
        };

        public void ApplyTo(ServerSettings settings)
        {
            settings.BlacklistedIps = EntryList.Parse(BlacklistedIps);
            settings.OnlyWhitelistedIps = OnlyWhitelistedIps;
            settings.WhitelistedIps = EntryList.Parse(WhitelistedIps);
            settings.MaxLoginAttemptsBeforeBan = MaxLoginAttemptsBeforeBan;
            settings.LoginFailureWindowSeconds = LoginFailureWindowSeconds;
            settings.BanDurationSeconds = BanDurationSeconds;
            settings.ExemptLoopbackFromBan = ExemptLoopbackFromBan;
        }
    }
}
