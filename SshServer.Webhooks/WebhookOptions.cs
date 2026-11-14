using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace SshServer.Webhooks;

/// <summary>The webhook options of the operator, section <c>Webhooks</c>. The webhooks themselves are in the settings database.</summary>
public sealed class WebhookOptions
{
    public const string SectionName = "Webhooks";
    public const int DefaultDeliveryRetentionDays = 30;
    public const int DefaultMaxConcurrentDeliveries = 4;

    /// <summary>
    /// Allows <c>http://</c> URLs to a loopback or private address (localhost, 127.0.0.0/8, ::1, 10/8, 172.16/12,
    /// 192.168/16, fc00::/7). Off: every URL must be <c>https://</c>.
    /// </summary>
    public bool AllowInsecureWebhooks { get; set; }

    /// <summary>Finished deliveries older than this many days are removed. 0: keep all.</summary>
    public int DeliveryRetentionDays { get; set; } = DefaultDeliveryRetentionDays;

    /// <summary>How many asynchronous deliveries this node sends at the same time.</summary>
    public int MaxConcurrentDeliveries { get; set; } = DefaultMaxConcurrentDeliveries;

    public static void Bind(WebhookOptions options, IConfiguration configuration)
    {
        options.AllowInsecureWebhooks = configuration.GetValue($"{SectionName}:{nameof(AllowInsecureWebhooks)}", false);
        options.DeliveryRetentionDays = configuration.GetValue($"{SectionName}:{nameof(DeliveryRetentionDays)}", DefaultDeliveryRetentionDays);
        options.MaxConcurrentDeliveries = configuration.GetValue($"{SectionName}:{nameof(MaxConcurrentDeliveries)}", DefaultMaxConcurrentDeliveries);
    }
}

public sealed class WebhookOptionsValidator : IValidateOptions<WebhookOptions>
{
    public ValidateOptionsResult Validate(string? name, WebhookOptions options)
    {
        var errors = new List<string>();
        if (options.DeliveryRetentionDays < 0)
            errors.Add($"{WebhookOptions.SectionName}:{nameof(WebhookOptions.DeliveryRetentionDays)} must be 0 (keep all) or more days.");
        if (options.MaxConcurrentDeliveries is < 1 or > 64)
            errors.Add($"{WebhookOptions.SectionName}:{nameof(WebhookOptions.MaxConcurrentDeliveries)} must be 1 to 64.");
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
