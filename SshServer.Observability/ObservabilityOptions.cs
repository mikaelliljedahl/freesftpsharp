using Microsoft.Extensions.Configuration;

namespace SshServer.Observability;

/// <summary>
/// The <c>Observability</c> section of the configuration. Everything is off by default: without this section no new
/// endpoint exists and nothing is exported.
/// </summary>
public sealed class ObservabilityOptions
{
    public const string SectionName = "Observability";

    /// <summary>The Prometheus scrape endpoint on the web host.</summary>
    public PrometheusOptions Prometheus { get; set; } = new();

    /// <summary>The OTLP export of metrics and, optionally, traces.</summary>
    public OtlpOptions Otlp { get; set; } = new();

    /// <summary>The health endpoints on the web host.</summary>
    public HealthOptions Health { get; set; } = new();

    public static ObservabilityOptions From(IConfiguration configuration)
    {
        var options = new ObservabilityOptions();
        configuration.GetSection(SectionName).Bind(options);
        return options;
    }
}

public sealed class PrometheusOptions
{
    /// <summary>Turns <see cref="Path"/> on. Default false.</summary>
    public bool Enabled { get; set; }

    public string Path { get; set; } = "/metrics";

    /// <summary>A caller with this key in <c>Authorization: Bearer</c> may scrape.</summary>
    public string? ApiKey { get; set; }

    /// <summary>
    /// A caller from one of these networks (CIDR, for example "10.0.0.0/8") or addresses may scrape. When neither this
    /// nor <see cref="ApiKey"/> is set, only loopback may scrape.
    /// </summary>
    public string[] AllowedNetworks { get; set; } = [];
}

public sealed class OtlpOptions
{
    /// <summary>The OTLP endpoint, for example "http://localhost:4317". Empty (default): no OTLP export.</summary>
    public string? Endpoint { get; set; }

    /// <summary>Also export the traces (an activity per session and per storage operation). Default false.</summary>
    public bool Tracing { get; set; }
}

public sealed class HealthOptions
{
    /// <summary>Turns <c>/healthz</c> and <c>/readyz</c> on. Default false.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Who may ask for the JSON detail (<c>?detail=true</c>) of the checks: the same rules as the scrape endpoint
    /// (<see cref="PrometheusOptions.ApiKey"/>, <see cref="PrometheusOptions.AllowedNetworks"/>, else loopback). Everybody else
    /// gets a plain 200 or 503.
    /// </summary>
    public bool Detail { get; set; } = true;
}
