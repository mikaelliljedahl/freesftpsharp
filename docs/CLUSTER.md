# Several nodes on one database

Several server nodes can run behind a load balancer on one settings database (#75), for availability and for
throughput. Everything here is opt-in: with no configuration the server is one node on a SQLite file, as before.

A ready example with PostgreSQL, two nodes and HAProxy is [`deploy/cluster/docker-compose.yml`](../deploy/cluster/docker-compose.yml)
with [`haproxy.cfg`](../deploy/cluster/haproxy.cfg).

## Settings database

| Key | Default | Meaning |
| --- | --- | --- |
| `Settings:Provider` | `Sqlite` | `Sqlite`, `PostgreSQL` or `SqlServer` (or `LiteDb`, obsolete) |
| `ConnectionStrings:Settings` | `Data Source=freesftpsharp.db` | The connection string of the provider. PostgreSQL: `Host=db;Database=freesftpsharp;Username=freesftpsharp;Password=...` (Npgsql). SQL Server: `Server=db;Database=freesftpsharp;User Id=...;Password=...;TrustServerCertificate=True` (SqlClient) |

The server creates and migrates the schema at the start, also when several nodes start at the same time (EF Core takes
a migration lock). The user needs the right to create tables; on PostgreSQL the first migration creates the `citext`
extension (a trusted extension: the owner of the database may create it). On SQL Server keep a case-insensitive
(`_CI_`) collation for the database: user, group and folder names compare without case on every provider.

Each provider is its own project with its own migrations: `SshServer.Settings.Sql` (SQLite, `Migrations/Sqlite`),
`SshServer.Settings.PostgreSql` and `SshServer.Settings.SqlServer` (`Migrations`). The hosts call
`AddPostgreSqlSettings()` and `AddSqlServerSettings()`; `Settings:Provider` selects one in `SettingsDatabase.Create`.

SQLite works for several processes on one machine (the tests do that), not for nodes on several machines.

## Cluster

| Key | Default | Meaning |
| --- | --- | --- |
| `Cluster:Enabled` | `false` | This node is one of several on the settings database |
| `Cluster:NodeId` | host name and a random suffix | The name of the node, unique among the nodes (at most 128 characters) |
| `Cluster:PollIntervalSeconds` | `5` | How often a node writes its heartbeat and reads the shared state (1-60) |
| `DataProtection:Store` | `FileSystem` | `Database`: the data protection keys are in the settings database (table `DataProtectionKeys`), so a login cookie, an API token and the encrypted secrets (webhooks, storage, TOTP) work on every node. `FileSystem`: `DataProtection:KeysPath`, which the nodes must then share |

With `Cluster:Enabled` every node, each poll interval (`ClusterNodeService`):

- writes its heartbeat (table `Nodes`) and its open connections (table `Connections`), and removes the nodes without a
  heartbeat for four intervals (at least 15 s) with their rows;
- reads the connections of the other nodes: the Connections page and `GET /api/v1/connections` list the connections of
  every node, each with its `node`. `DELETE /api/v1/connections/{id}` and the Disconnect button close a connection of
  another node through a row in `DisconnectRequests`, which that node reads at its next poll;
- takes the shared bans (table `BannedIps`): a ban of one node is refused on every node, and lifting it on one node lifts
  it on all (the failed logins are counted per node);
- reads the settings version (table `SettingsVersions`, raised by every change of users, groups, folders, settings,
  webhooks, rules and administrators): when another node changed something, the in-memory caches of the webhooks and the
  event rules reload.

The users, groups and server settings are read from the database for each login, so a user created on one node can log
in on the others at once. The quota counters (#62) are increments in the database, the webhook outbox (#66) and the
schedule of the event rules (#68) are claimed with conditional updates, and the token signing key of the REST API (#67)
is in the database: they work on several nodes without more settings. The session limit of a user (`MaxSessions`) is
counted per node. A user closed on one node (disabled or removed) is disconnected on every node.

The files of the users must be on storage that every node reaches: a shared file system for the local disk backend, or
an object store (S3, Azure Blob, GCS).

## Load balancer and the PROXY protocol

SFTP needs no sticky sessions: every SSH connection is complete on one node. Behind a TCP load balancer the server sees
the address of the balancer; the PROXY protocol (HAProxy `send-proxy` or `send-proxy-v2`, also offered by the cloud
load balancers) gives it the address of the client.

| Key | Default | Meaning |
| --- | --- | --- |
| `Proxy:AllowedSources` | empty (off) | The addresses or CIDR networks of the load balancers, a list or a comma separated text |
| `Proxy:HeaderTimeoutSeconds` | `5` | The time for the PROXY header after the connection (1-60) |

With `Proxy:AllowedSources` every SSH connection must come from an allowed source and start with a PROXY header
(version 1 or 2). The client address of the header is then used for the IP rules, the bans, the connections and the
audit log. A connection from another source, without a header, or with a header that is not valid is closed before the
SSH handshake. A `LOCAL` (v2) or `UNKNOWN` (v1) header keeps the address of the balancer (health checks).

The admin UI and the REST API are HTTP. With `DataProtection:Store=Database` the login cookie works on every node; the
interactive Blazor UI keeps its circuit on one node, so give the browser a sticky cookie (the example does). The REST API
needs none.
