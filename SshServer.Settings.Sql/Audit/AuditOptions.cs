using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace SshServer.Settings.Sql.Audit;

/// <summary>The audit log options, section <c>Audit</c>.</summary>
public sealed class AuditOptions
{
    public const string SectionName = "Audit";
    public const int DefaultRetentionDays = 90;

    /// <summary>Entries older than this many days are removed every night. 0: keep all entries.</summary>
    public int RetentionDays { get; set; } = DefaultRetentionDays;

    public static void Bind(AuditOptions options, IConfiguration configuration)
    {
        options.RetentionDays = configuration.GetValue($"{SectionName}:RetentionDays", DefaultRetentionDays);
    }
}

public sealed class AuditOptionsValidator : IValidateOptions<AuditOptions>
{
    public ValidateOptionsResult Validate(string? name, AuditOptions options)
        => options.RetentionDays < 0
            ? ValidateOptionsResult.Fail($"{AuditOptions.SectionName}:RetentionDays must be 0 (keep all) or more days, not {options.RetentionDays}.")
            : ValidateOptionsResult.Success;
}
