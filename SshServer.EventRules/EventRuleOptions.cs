using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace SshServer.EventRules;

/// <summary>The event rule options of the operator, section <c>EventRules</c>. The rules themselves are in the settings database.</summary>
public sealed class EventRuleOptions
{
    public const string SectionName = "EventRules";
    public const int DefaultCommandTimeoutSeconds = 30;
    public const int DefaultMaxConcurrentRuns = 4;
    public const int DefaultRunHistoryPerRule = 100;
    public const int DefaultSyncTimeoutSeconds = 30;

    /// <summary>
    /// Allows the Command action. Off (default): a rule with a Command action cannot be saved and a stored one is refused
    /// when it runs. Even when on, only the executables in <see cref="AllowedCommands"/> can run.
    /// </summary>
    public bool AllowCommands { get; set; }

    /// <summary>The absolute paths of the executables that a Command action may start.</summary>
    public List<string> AllowedCommands { get; set; } = new();

    /// <summary>The longest time of one command; then it is killed.</summary>
    public int CommandTimeoutSeconds { get; set; } = DefaultCommandTimeoutSeconds;

    /// <summary>How many rule runs of events this node does at the same time.</summary>
    public int MaxConcurrentRuns { get; set; } = DefaultMaxConcurrentRuns;

    /// <summary>How many runs of each rule the execution history keeps.</summary>
    public int RunHistoryPerRule { get; set; } = DefaultRunHistoryPerRule;

    /// <summary>The longest time that an upload, download or delete waits for the rules of its <c>Pre*</c> event; then it is refused.</summary>
    public int SyncTimeoutSeconds { get; set; } = DefaultSyncTimeoutSeconds;

    /// <summary>The mail server of the Email action. Without <see cref="SmtpOptions.Host"/> an Email action is skipped.</summary>
    public SmtpOptions Smtp { get; set; } = new();

    public static void Bind(EventRuleOptions options, IConfiguration configuration)
    {
        var section = configuration.GetSection(SectionName);
        options.AllowCommands = section.GetValue(nameof(AllowCommands), false);
        options.AllowedCommands = section.GetSection(nameof(AllowedCommands)).Get<List<string>>() ?? new();
        options.CommandTimeoutSeconds = section.GetValue(nameof(CommandTimeoutSeconds), DefaultCommandTimeoutSeconds);
        options.MaxConcurrentRuns = section.GetValue(nameof(MaxConcurrentRuns), DefaultMaxConcurrentRuns);
        options.RunHistoryPerRule = section.GetValue(nameof(RunHistoryPerRule), DefaultRunHistoryPerRule);
        options.SyncTimeoutSeconds = section.GetValue(nameof(SyncTimeoutSeconds), DefaultSyncTimeoutSeconds);
        section.GetSection(nameof(Smtp)).Bind(options.Smtp);
    }
}

/// <summary>How the connection to the mail server is secured.</summary>
public enum SmtpSecurity
{
    /// <summary>STARTTLS when the server offers it (port 25 and 587), implicit TLS on port 465.</summary>
    Auto,
    None,
    StartTls,
    SslOnConnect,
}

/// <summary>The SMTP settings of the Email action, section <c>EventRules:Smtp</c>.</summary>
public sealed class SmtpOptions
{
    public const int DefaultPort = 587;
    public const long DefaultMaxAttachmentBytes = 10 * 1024 * 1024;

    /// <summary>The mail server. Empty (default): no email is sent.</summary>
    public string? Host { get; set; }

    public int Port { get; set; } = DefaultPort;

    public SmtpSecurity Security { get; set; } = SmtpSecurity.Auto;

    /// <summary>The login at the mail server; empty: no login.</summary>
    public string? Username { get; set; }

    /// <summary>The password of <see cref="Username"/>. A secret: never shown in the UI or the log.</summary>
    public string? Password { get; set; }

    /// <summary>The sender address, for example <c>sftp@example.com</c>.</summary>
    public string? From { get; set; }

    /// <summary>The largest file that an Email action attaches; a larger file is not attached.</summary>
    public long MaxAttachmentBytes { get; set; } = DefaultMaxAttachmentBytes;

    public bool IsConfigured => !string.IsNullOrWhiteSpace(Host);
}

public sealed class EventRuleOptionsValidator : IValidateOptions<EventRuleOptions>
{
    public ValidateOptionsResult Validate(string? name, EventRuleOptions options)
    {
        var errors = new List<string>();
        var prefix = EventRuleOptions.SectionName + ":";
        if (options.CommandTimeoutSeconds is < 1 or > 3600)
            errors.Add($"{prefix}{nameof(EventRuleOptions.CommandTimeoutSeconds)} must be 1 to 3600 seconds.");
        if (options.MaxConcurrentRuns is < 1 or > 64)
            errors.Add($"{prefix}{nameof(EventRuleOptions.MaxConcurrentRuns)} must be 1 to 64.");
        if (options.RunHistoryPerRule is < 1 or > 10_000)
            errors.Add($"{prefix}{nameof(EventRuleOptions.RunHistoryPerRule)} must be 1 to 10000.");
        if (options.SyncTimeoutSeconds is < 1 or > 300)
            errors.Add($"{prefix}{nameof(EventRuleOptions.SyncTimeoutSeconds)} must be 1 to 300 seconds.");
        foreach (var command in options.AllowedCommands)
        {
            if (string.IsNullOrWhiteSpace(command) || !Path.IsPathFullyQualified(command))
                errors.Add($"{prefix}{nameof(EventRuleOptions.AllowedCommands)} must have absolute paths, not '{command}'.");
        }
        if (options.Smtp.IsConfigured)
        {
            if (options.Smtp.Port is < 1 or > 65535)
                errors.Add($"{prefix}Smtp:Port must be 1 to 65535.");
            if (string.IsNullOrWhiteSpace(options.Smtp.From))
                errors.Add($"{prefix}Smtp:From is needed with Smtp:Host (the sender address).");
            if (options.Smtp.MaxAttachmentBytes < 0)
                errors.Add($"{prefix}Smtp:MaxAttachmentBytes must be 0 or more.");
        }
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
