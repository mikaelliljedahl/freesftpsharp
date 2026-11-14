using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using FxSsh.SshServerModule;
using SshServer.Interfaces;

namespace SshServer.Observability;

/// <summary>Ready when the settings database answers.</summary>
internal sealed class DatabaseHealthCheck(ISettingsRepository settings) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            return Task.FromResult(settings.ServerSettings != null && settings.GetAllUsers() != null
                ? HealthCheckResult.Healthy("The settings database answers.")
                : HealthCheckResult.Unhealthy("The settings database gave no data."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("The settings database is not readable.", ex));
        }
    }
}

/// <summary>Ready when the SSH listeners are bound. A host without the SSH server (no <see cref="HostedServer"/>) is not asked.</summary>
internal sealed class ListenerHealthCheck(IEnumerable<IHostedService> hosted) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var servers = hosted.OfType<HostedServer>().ToList();
        if (servers.Count == 0)
            return Task.FromResult(HealthCheckResult.Healthy("No SSH listener in this host."));
        return Task.FromResult(servers.All(s => s.IsListening)
            ? HealthCheckResult.Healthy("The SSH listeners are bound.")
            : HealthCheckResult.Unhealthy("The SSH listeners are not bound."));
    }
}
