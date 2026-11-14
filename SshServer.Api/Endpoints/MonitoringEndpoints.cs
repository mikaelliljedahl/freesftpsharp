using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using SshServer.Administration;
using SshServer.Interfaces;
using SshServer.Interfaces.Audit;
using SshServer.Interfaces.Connections;

namespace SshServer.Api.Endpoints;

/// <summary>An active auto-ban of a client address.</summary>
public sealed record IpBanView(string Address, DateTimeOffset BannedAt, DateTimeOffset ExpiresAt, int FailedAttempts);

/// <summary>
/// /api/v1/connections (#57), /api/v1/audit (#65) and /api/v1/ip-bans (#43), over the scoped services of the Connections
/// and Audit pages (<see cref="ScopedConnections"/>, <see cref="ScopedAuditLog"/>: a scoped administrator sees only the
/// connections and entries of its users) and <see cref="IIpBanService"/> (the Access page, ManageSettings).
/// </summary>
internal static class MonitoringEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        var connections = api.MapGroup("/connections").WithTags("Connections");

        connections.MapGet("/", (ScopedConnections registry, int? offset, int? limit) =>
                TypedResults.Ok(Paging.Of(registry.GetAll().OrderBy(c => c.ConnectedAt), offset, limit, c => c)))
            .WithName("ListConnections").RequireAuthorization(AdminPolicies.ViewConnections).WithValidationErrors();

        connections.MapDelete("/{id:guid}", async Task<Results<NoContent, ProblemHttpResult>> (ScopedConnections registry, Guid id, string? reason) =>
                await registry.DisconnectAsync(id, string.IsNullOrWhiteSpace(reason) ? "Disconnected by an administrator (REST API)." : reason.Trim())
                    ? TypedResults.NoContent()
                    : ApiResults.NotFound($"The connection {id} is not open."))
            .WithName("Disconnect").WithSummary("Closes a connection.")
            .RequireAuthorization(AdminPolicies.DisconnectConnections).RequireAuthorization(AdminPolicies.ViewConnections)
            .WithErrors().WithNotFound();

        api.MapGet("/audit", async (ScopedAuditLog audit, string? username, string? type, string? status, DateTime? from, DateTime? to,
                int? offset, int? limit, CancellationToken ct) =>
            {
                var (skip, take) = Paging.Validate(offset, limit);
                var result = await audit.QueryAsync(new AuditQuery
                {
                    Username = Clean(username),
                    Type = Clean(type),
                    Status = Clean(status),
                    FromUtc = from?.ToUniversalTime(),
                    ToUtc = to?.ToUniversalTime(),
                    Skip = skip,
                    Take = take,
                }, ct);
                return TypedResults.Ok(new Page<AuditEntry>(result.Entries, result.TotalCount, skip, take));
            })
            .WithTags("Audit").WithName("QueryAudit").WithSummary("The audit log, newest first, with filters.")
            .RequireAuthorization(AdminPolicies.ViewAudit).WithValidationErrors();

        var bans = api.MapGroup("/ip-bans").WithTags("IP bans").RequireAuthorization(AdminPolicies.ManageSettings);

        bans.MapGet("/", (IIpBanService service) =>
                TypedResults.Ok(service.GetActiveBans().Select(b => new IpBanView(b.Address.ToString(), b.BannedAt, b.ExpiresAt, b.FailedAttempts)).ToList()))
            .WithName("ListIpBans").WithSummary("The active auto-bans of client addresses.").WithErrors();

        bans.MapDelete("/{address}", Results<NoContent, ProblemHttpResult> (IIpBanService service, string address) =>
            {
                if (!IPAddress.TryParse(address, out var ip))
                    throw new ApiValidationException("address", $"'{address}' is not an IP address.");
                return service.Unban(ip) ? TypedResults.NoContent() : ApiResults.NotFound($"The address {ip} is not banned.");
            })
            .WithName("LiftIpBan").WithValidationErrors().WithNotFound();
    }

    private static string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
