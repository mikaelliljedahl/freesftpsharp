using System;
using Microsoft.Extensions.Options;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The configuration section "WebClient" (#69): the browser client of the SFTP users at <c>/client</c>. Off by
    /// default: without <c>WebClient:Enabled</c> every <c>/client</c> path answers 404, so a server that only serves SFTP
    /// does not offer a second login page.
    /// </summary>
    public sealed class WebClientOptions
    {
        public const string SectionName = "WebClient";

        /// <summary>Turns the web client on. Default false.</summary>
        public bool Enabled { get; set; }

        /// <summary>
        /// Allow the web client over plain HTTP from other hosts than loopback. Default false: the password and the login
        /// cookie travel only over HTTPS.
        /// </summary>
        public bool AllowInsecureHttp { get; set; }

        /// <summary>Failed logins (passwords and codes) from one client address before it is locked out.</summary>
        public int MaxFailedLogins { get; set; } = 5;

        public int LockoutMinutes { get; set; } = 15;

        /// <summary>A browser session ends after this many minutes without a request. It also ends at logout.</summary>
        public int SessionIdleMinutes { get; set; } = 30;

        /// <summary>The size of one upload request (the browser sends a file in chunks of this size).</summary>
        public int UploadChunkBytes { get; set; } = 8 * 1024 * 1024;

        /// <summary>An unfinished upload is aborted after this many minutes without a chunk.</summary>
        public int UploadIdleMinutes { get; set; } = 30;

        /// <summary>The unfinished uploads one session can have at the same time.</summary>
        public int MaxUploadsPerSession { get; set; } = 16;

        /// <summary>The requests per client address and minute on the share links (#70); more get 429.</summary>
        public int ShareRequestsPerMinute { get; set; } = 300;

        public TimeSpan SessionIdle => TimeSpan.FromMinutes(SessionIdleMinutes);

        public TimeSpan UploadIdle => TimeSpan.FromMinutes(UploadIdleMinutes);
    }

    /// <summary>Checks <see cref="WebClientOptions"/> at the start.</summary>
    public sealed class WebClientOptionsValidator : IValidateOptions<WebClientOptions>
    {
        /// <summary>The largest chunk: the default request body limit of Kestrel is 30 MB.</summary>
        public const int MaxChunkBytes = 28 * 1024 * 1024;

        public ValidateOptionsResult Validate(string name, WebClientOptions options)
        {
            if (options.MaxFailedLogins < 1)
                return ValidateOptionsResult.Fail("WebClient:MaxFailedLogins must be at least 1.");
            if (options.LockoutMinutes < 1)
                return ValidateOptionsResult.Fail("WebClient:LockoutMinutes must be at least 1.");
            if (options.SessionIdleMinutes < 1)
                return ValidateOptionsResult.Fail("WebClient:SessionIdleMinutes must be at least 1.");
            if (options.UploadChunkBytes < 64 * 1024 || options.UploadChunkBytes > MaxChunkBytes)
                return ValidateOptionsResult.Fail($"WebClient:UploadChunkBytes must be between 65536 and {MaxChunkBytes}.");
            if (options.UploadIdleMinutes < 1)
                return ValidateOptionsResult.Fail("WebClient:UploadIdleMinutes must be at least 1.");
            if (options.MaxUploadsPerSession < 1)
                return ValidateOptionsResult.Fail("WebClient:MaxUploadsPerSession must be at least 1.");
            if (options.ShareRequestsPerMinute < 1)
                return ValidateOptionsResult.Fail("WebClient:ShareRequestsPerMinute must be at least 1.");
            return ValidateOptionsResult.Success;
        }
    }
}
