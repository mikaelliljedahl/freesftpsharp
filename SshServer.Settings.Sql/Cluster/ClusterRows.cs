namespace SshServer.Settings.Sql.Cluster;

/// <summary>A row of the table BannedIps: a shared ban (issue #75). The times are UTC.</summary>
public sealed class BannedIpRow
{
    public string Address { get; set; } = string.Empty;
    public DateTime BannedUtc { get; set; }
    public DateTime ExpiresUtc { get; set; }
    public int FailedAttempts { get; set; }
}

/// <summary>A row of the table Nodes: a server node with its heartbeat (UTC).</summary>
public sealed class NodeRow
{
    public string NodeId { get; set; } = string.Empty;
    public string Hostname { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public DateTime StartedUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
}

/// <summary>A row of the table Connections: an open connection of a node at its last heartbeat (times UTC, transfers as JSON).</summary>
public sealed class ConnectionRow
{
    public Guid Id { get; set; }
    public string NodeId { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public string RemoteEndPoint { get; set; } = string.Empty;
    public string? ClientVersion { get; set; }
    public DateTime ConnectedUtc { get; set; }
    public DateTime LastActivityUtc { get; set; }
    public string? Username { get; set; }
    public DateTime? AuthenticatedUtc { get; set; }
    public string? AuthMethod { get; set; }
    public string Transfers { get; set; } = "[]";
}

/// <summary>A row of the table DisconnectRequests: another node asks the node to close one of its connections.</summary>
public sealed class DisconnectRequestRow
{
    public long Id { get; set; }
    public string NodeId { get; set; } = string.Empty;
    public Guid ConnectionId { get; set; }
    public string Reason { get; set; } = string.Empty;
    public DateTime CreatedUtc { get; set; }
}

/// <summary>The one row of the table SettingsVersions: grows with every change of the settings.</summary>
public sealed class SettingsVersionRow
{
    public const int SingleId = 1;

    public int Id { get; set; }
    public long Version { get; set; }
}

/// <summary>A row of the table DataProtectionKeys: one XML element of the ASP.NET Core data protection key ring.</summary>
public sealed class DataProtectionKeyRow
{
    public int Id { get; set; }
    public string? FriendlyName { get; set; }
    public string Xml { get; set; } = string.Empty;
}
