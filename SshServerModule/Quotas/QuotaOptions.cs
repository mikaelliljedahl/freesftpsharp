#nullable enable
using System;
using System.Globalization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace SshServerModule.Quotas
{
    /// <summary>The quota options, section <c>Quota</c> (issue #62). The quotas themselves are set per user.</summary>
    public sealed class QuotaOptions
    {
        public const string SectionName = "Quota";
        public const int DefaultScanIntervalHours = 24;

        /// <summary>
        /// Every this many hours the disk usage of every storage with a quota is scanned again, which corrects changes
        /// made outside the server. 0: no scheduled scan (the admin UI can still start one).
        /// </summary>
        public int ScanIntervalHours { get; set; } = DefaultScanIntervalHours;

        /// <summary>The quota counters are written to the settings database this often (and when the server stops).</summary>
        public TimeSpan FlushInterval { get; set; } = TimeSpan.FromSeconds(5);

        public static void Bind(QuotaOptions options, IConfiguration configuration)
        {
            var text = configuration[$"{SectionName}:ScanIntervalHours"];
            // Text that is not a number is -1, which the validator refuses at start.
            options.ScanIntervalHours = string.IsNullOrWhiteSpace(text) ? DefaultScanIntervalHours
                : int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var hours) ? hours : -1;
        }
    }

    public sealed class QuotaOptionsValidator : IValidateOptions<QuotaOptions>
    {
        public ValidateOptionsResult Validate(string? name, QuotaOptions options)
            => options.ScanIntervalHours < 0
                ? ValidateOptionsResult.Fail($"{QuotaOptions.SectionName}:ScanIntervalHours must be 0 (no scheduled scan) or more hours, not {options.ScanIntervalHours}.")
                : ValidateOptionsResult.Success;
    }
}
