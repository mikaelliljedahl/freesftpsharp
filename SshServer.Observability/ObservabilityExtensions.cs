using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using SshServerModule.Observability;

namespace SshServer.Observability;

public static class ObservabilityExtensions
{
    public const string ReadyTag = "ready";

    /// <summary>
    /// Opt-in exporters and health checks, from the <c>Observability</c> section (see <see cref="ObservabilityOptions"/>).
    /// It always registers the metric instruments of the core. With an empty section it exports nothing and adds no endpoint.
    /// </summary>
    public static IServiceCollection AddSshServerObservability(this IServiceCollection services, IConfiguration configuration)
    {
        var options = ObservabilityOptions.From(configuration);
        services.AddSshServerMetrics();
        services.AddSingleton(options);

        var otlp = !string.IsNullOrWhiteSpace(options.Otlp.Endpoint);
        if (options.Prometheus.Enabled || otlp)
        {
            var telemetry = services.AddOpenTelemetry().WithMetrics(metrics =>
            {
                metrics.AddMeter(Telemetry.MeterName).AddAspNetCoreInstrumentation().AddRuntimeInstrumentation();
                if (options.Prometheus.Enabled)
                    metrics.AddPrometheusExporter();
                if (otlp)
                    metrics.AddOtlpExporter(o => o.Endpoint = new Uri(options.Otlp.Endpoint!));
            });
            if (otlp && options.Otlp.Tracing)
                telemetry.WithTracing(tracing => tracing.AddSource(Telemetry.ActivitySourceName)
                    .AddOtlpExporter(o => o.Endpoint = new Uri(options.Otlp.Endpoint!)));
        }

        if (options.Health.Enabled)
        {
            services.AddHealthChecks()
                .AddCheck<DatabaseHealthCheck>("database", tags: [ReadyTag])
                .AddCheck<ListenerHealthCheck>("listeners", tags: [ReadyTag]);
        }
        return services;
    }

    /// <summary>
    /// Maps the Prometheus scrape endpoint and <c>/healthz</c>, <c>/readyz</c> when they are turned on. They are terminal
    /// middleware: call it first in the pipeline, before the login, HTTPS redirection and routing, so that a probe or a
    /// scraper needs neither a cookie nor HTTPS. The scrape endpoint is for the operator (key or network), the health
    /// endpoints answer plain 200 or 503 to everybody.
    /// </summary>
    public static WebApplication UseSshServerObservability(this WebApplication app)
    {
        var options = app.Services.GetRequiredService<ObservabilityOptions>();
        var access = new OperatorAccess(options.Prometheus);

        if (options.Prometheus.Enabled)
        {
            var path = options.Prometheus.Path;
            app.Use(async (context, next) =>
            {
                if (context.Request.Path.Equals(path, StringComparison.OrdinalIgnoreCase) && !access.IsAllowed(context))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.Headers.WWWAuthenticate = "Bearer";
                    return;
                }
                await next();
            });
            app.UseOpenTelemetryPrometheusScrapingEndpoint(path);
        }

        if (options.Health.Enabled)
        {
            app.Use(async (context, next) =>
            {
                var path = context.Request.Path;
                if (path.Equals("/healthz", StringComparison.OrdinalIgnoreCase))
                {
                    // Liveness: the process answers. No check runs.
                    context.Response.StatusCode = StatusCodes.Status200OK;
                    context.Response.ContentType = "text/plain";
                    await context.Response.WriteAsync("Healthy");
                }
                else if (path.Equals("/readyz", StringComparison.OrdinalIgnoreCase))
                {
                    var report = await context.RequestServices.GetRequiredService<HealthCheckService>()
                        .CheckHealthAsync(r => r.Tags.Contains(ReadyTag), context.RequestAborted);
                    context.Response.StatusCode = report.Status == HealthStatus.Healthy ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable;
                    if (options.Health.Detail && context.Request.Query.ContainsKey("detail") && access.IsAllowed(context))
                    {
                        context.Response.ContentType = "application/json";
                        await JsonSerializer.SerializeAsync(context.Response.Body, new
                        {
                            status = report.Status.ToString(),
                            checks = report.Entries.ToDictionary(e => e.Key, e => new
                            {
                                status = e.Value.Status.ToString(),
                                description = e.Value.Description,
                                error = e.Value.Exception?.Message,
                            }),
                        });
                    }
                    else
                    {
                        context.Response.ContentType = "text/plain";
                        await context.Response.WriteAsync(report.Status.ToString());
                    }
                }
                else
                {
                    await next();
                }
            });
        }
        return app;
    }
}
