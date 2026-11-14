using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using SshServer.Interfaces.Cluster;
using SshServer.Interfaces.Connections;

namespace SshServer.Settings.Sql.Cluster;

/// <summary>
/// <see cref="IClusterStore"/> and <see cref="ISettingsVersionStore"/> in the settings database (issue #75): the tables
/// Nodes, Connections, DisconnectRequests and SettingsVersions. A node writes only its own rows. Each call has its own context.
/// </summary>
public sealed class SqlClusterStore : IClusterStore, ISettingsVersionStore
{
    private static readonly JsonSerializerOptions Json = new() { Converters = { new JsonStringEnumConverter() } };

    private readonly DbContextOptions<SettingsDbContext> _options;

    public SqlClusterStore(DbContextOptions<SettingsDbContext> options)
    {
        _options = options;
    }

    private SettingsDbContext CreateContext() => new(_options);

    public async Task HeartbeatAsync(NodeInfo node, IReadOnlyList<ConnectionInfo> connections, CancellationToken ct)
    {
        await using var db = CreateContext();
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var row = await db.Nodes.FirstOrDefaultAsync(n => n.NodeId == node.NodeId, ct);
        if (row == null)
            db.Nodes.Add(row = new NodeRow { NodeId = node.NodeId });
        row.Hostname = Truncate(node.Hostname, 256);
        row.Version = Truncate(node.Version, 64);
        row.StartedUtc = node.StartedAt.UtcDateTime;
        row.LastSeenUtc = node.LastSeen.UtcDateTime;

        await db.Connections.Where(c => c.NodeId == node.NodeId).ExecuteDeleteAsync(ct);
        db.Connections.AddRange(connections.Select(c => ToRow(node.NodeId, c)));
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
    }

    public async Task<IReadOnlyList<NodeInfo>> ListNodesAsync(CancellationToken ct)
    {
        await using var db = CreateContext();
        var rows = await db.Nodes.AsNoTracking().OrderBy(n => n.NodeId).ToListAsync(ct);
        return rows.Select(n => new NodeInfo(n.NodeId, n.Hostname, n.Version, Utc(n.StartedUtc), Utc(n.LastSeenUtc))).ToList();
    }

    public async Task<IReadOnlyList<ConnectionInfo>> ListConnectionsAsync(DateTimeOffset aliveSince, CancellationToken ct)
    {
        await using var db = CreateContext();
        var since = aliveSince.UtcDateTime;
        var alive = db.Nodes.Where(n => n.LastSeenUtc >= since).Select(n => n.NodeId);
        var rows = await db.Connections.AsNoTracking().Where(c => alive.Contains(c.NodeId)).ToListAsync(ct);
        return rows.OrderBy(r => r.ConnectedUtc).Select(FromRow).ToList();
    }

    public async Task RequestDisconnectAsync(string nodeId, Guid connectionId, string reason, DateTimeOffset now, CancellationToken ct)
    {
        await using var db = CreateContext();
        db.DisconnectRequests.Add(new DisconnectRequestRow
        {
            NodeId = nodeId, ConnectionId = connectionId, Reason = Truncate(reason, 512), CreatedUtc = now.UtcDateTime,
        });
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<DisconnectRequest>> TakeDisconnectRequestsAsync(string nodeId, CancellationToken ct)
    {
        await using var db = CreateContext();
        var rows = await db.DisconnectRequests.AsNoTracking().Where(r => r.NodeId == nodeId).OrderBy(r => r.Id).ToListAsync(ct);
        if (rows.Count == 0)
            return [];
        var last = rows[^1].Id;
        await db.DisconnectRequests.Where(r => r.NodeId == nodeId && r.Id <= last).ExecuteDeleteAsync(ct);
        return rows.Select(r => new DisconnectRequest(r.Id, r.NodeId, r.ConnectionId, r.Reason)).ToList();
    }

    public async Task RemoveNodeAsync(string nodeId, CancellationToken ct)
    {
        await using var db = CreateContext();
        await db.Connections.Where(c => c.NodeId == nodeId).ExecuteDeleteAsync(ct);
        await db.DisconnectRequests.Where(r => r.NodeId == nodeId).ExecuteDeleteAsync(ct);
        await db.Nodes.Where(n => n.NodeId == nodeId).ExecuteDeleteAsync(ct);
    }

    public async Task<int> RemoveStaleNodesAsync(DateTimeOffset seenBefore, CancellationToken ct)
    {
        await using var db = CreateContext();
        var before = seenBefore.UtcDateTime;
        var stale = await db.Nodes.AsNoTracking().Where(n => n.LastSeenUtc < before).Select(n => n.NodeId).ToListAsync(ct);
        foreach (var nodeId in stale)
            await RemoveNodeAsync(nodeId, ct);
        return stale.Count;
    }

    public async Task<long> GetAsync(CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.SettingsVersions.AsNoTracking().Where(v => v.Id == SettingsVersionRow.SingleId)
            .Select(v => v.Version).FirstOrDefaultAsync(ct);
    }

    public async Task BumpAsync(CancellationToken ct)
    {
        await using var db = CreateContext();
        for (var attempt = 0; attempt < 3; attempt++)
        {
            if (await db.SettingsVersions.Where(v => v.Id == SettingsVersionRow.SingleId)
                    .ExecuteUpdateAsync(s => s.SetProperty(v => v.Version, v => v.Version + 1), ct) > 0)
                return;
            db.SettingsVersions.Add(new SettingsVersionRow { Id = SettingsVersionRow.SingleId, Version = 1 });
            try
            {
                await db.SaveChangesAsync(ct);
                return;
            }
            catch (DbUpdateException)
            {
                // Another node inserted the row first: add to it.
                db.ChangeTracker.Clear();
            }
        }
    }

    private static ConnectionRow ToRow(string nodeId, ConnectionInfo c) => new()
    {
        Id = c.Id,
        NodeId = nodeId,
        Protocol = Truncate(c.Protocol, 32),
        RemoteEndPoint = Truncate(c.RemoteEndPoint, 128),
        ClientVersion = c.ClientVersion == null ? null : Truncate(c.ClientVersion, 256),
        ConnectedUtc = c.ConnectedAt.UtcDateTime,
        LastActivityUtc = c.LastActivity.UtcDateTime,
        Username = c.Username,
        AuthenticatedUtc = c.AuthenticatedAt?.UtcDateTime,
        AuthMethod = c.AuthMethod == null ? null : Truncate(c.AuthMethod, 64),
        Transfers = JsonSerializer.Serialize(c.Transfers, Json),
    };

    private static ConnectionInfo FromRow(ConnectionRow r) => new(
        r.Id, r.Protocol, r.RemoteEndPoint, r.ClientVersion, Utc(r.ConnectedUtc), Utc(r.LastActivityUtc), r.Username,
        r.AuthenticatedUtc is { } authenticated ? Utc(authenticated) : null, r.AuthMethod,
        JsonSerializer.Deserialize<List<ActiveTransfer>>(r.Transfers, Json) ?? [])
    {
        Node = r.NodeId,
    };

    private static DateTimeOffset Utc(DateTime value) => new(DateTime.SpecifyKind(value, DateTimeKind.Utc));

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];
}
