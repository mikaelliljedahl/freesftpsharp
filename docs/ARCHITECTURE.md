# Architecture rules

These rules keep the server easy to maintain while it grows. They apply to all new code and to every
roadmap item in [ROADMAP.md](ROADMAP.md). If a change cannot follow a rule, explain why in the pull request.

## Simple by default

Many people use the server only as a simple local test server. That use must stay easy.

- **Zero configuration to start.** `ServerConsoleApp` with no arguments and no configuration file starts an
  SFTP server on local disk. It creates the SQLite database and the host keys itself.
- **Every new feature is opt-in.** A new backend, hook, authentication provider, protocol or limit is off
  until an operator turns it on. A new feature never adds a required setting.
- **Safe defaults.** A default value works on a developer machine and is secure. If a feature needs a secret
  (for example the admin password), the feature stays off and the log tells how to turn it on. The server
  does not stop.
- **No external services by default.** The default start needs no cloud account, no database server and no
  container.
- **Optional packages stay optional.** The core and the console host do not need the cloud SDKs to start.
- **Tested.** A test starts the server with an empty configuration and connects with an SFTP client. Keep
  this test green.

## Plug-in points

The server has a small core and a set of plug-in points. Each plug-in point is an interface in
`SshServer.Interfaces`. The core uses only the interface. It never knows which implementation it uses.

| Plug-in point | Interface | Examples | Issue |
|---|---|---|---|
| Storage backend | `IFileSystem` + `IStorageProvider` | local disk, encrypted local disk, S3, Azure Blob, GCS | #51, #56 |
| Storage rule | `IFileSystem` decorator | permissions, path filters, quotas, bandwidth, events | #59, #62, #65 |
| Authentication | `IAuthenticationProvider` | database, external HTTP, LDAP | #64 |
| Event sink | `IEventSink` / `IEventHook` on `IEventBus` | audit log, webhooks, event rules, metrics | #65, #66, #68 |
| Event rule action | `IEventRuleAction` | email, command, move, copy, delete, retention, webhook | #68 |
| Settings store | `ISettingsRepository` on an `ISettingsDatabaseProvider` | SQLite, PostgreSQL, SQL Server | #13, #75 |
| Protocol | hosted service or web host branch over the shared services | SFTP, WebDAV, FTP/S, HTTPS | #71, #72 |

## Connections

Every protocol registers its open connections in the `IConnectionRegistry` singleton (`SshServer.Interfaces.Connections`,
`AddSshServerConnections()`): it registers at accept, sets the user after the login, unregisters on close, and gives a
callback that closes the connection, so `DisconnectAsync` works for every protocol. The registry gives each connection
a stable `ConnectionInfo.Id` (a GUID) for the whole connection; later features (session limits, events, metrics) use it.
The registry is in memory and per node; with several nodes `IClusterConnections` adds the connections of the other
nodes (see "Several nodes").

A protocol without connections (WebDAV over HTTP) registers a session instead: one entry per client address and
credential, from the first successful login until it is idle (`WebDavSessionStore`).

The `ConnectionTrackingFileSystem` decorator keeps the registry entry up to date (last activity, open files with their
byte counts). The protocol passes the connection id in the `ClientContext` of `IFileSystemFactory.CreateAsync`, and the
factory adds the decorator to its chain.

## Protocols and logins

A protocol is a plug-in project with an `AddX()` (for example `FreeSftpSharp.WebDav`, `AddWebDav()` and `MapWebDav()`,
see [WEBDAV.md](WEBDAV.md), and `FreeSftpSharp.Ftp`, `AddFtp()`, a hosted service with its own listener, see
[FTP.md](FTP.md)); it is off until the operator turns it on. It uses only the shared services: the user's
`IFileSystem` from `IFileSystemFactory` (with a `ClientContext` of its protocol name), the `IConnectionRegistry`, the
`IEventBus`, and for a user name and password the `PasswordLoginService` (`AddSshServerSecurity()`). That service has
the login rules of the protocols other than SSH in one place: the global IP rules and the auto-ban, the IP whitelist of
the user, the password (`AllowedAuthMethods`; not alone for a multi-step login or a TOTP user), the app passwords
(`User.AppPasswords`, per protocol) and the protocol flags (`User.AllowedProtocols`). The SFTP login of `HostedServer`
checks the same flags. A protocol never repeats a storage rule.

The web client of the users (#69, [WEB-CLIENT.md](WEB-CLIENT.md)) is a branch of the web host (`FxSshSftpServer/WebClient`,
`AddWebClient()`, `UseWebClient()` and `MapWebClient()`, Razor Pages in `Pages/Client`), off unless `WebClient:Enabled`.
It logs in with `PasswordLoginService` in its interactive mode (`PasswordLoginOptions.Interactive`: the caller asks for the
TOTP code and lets an expired password be changed; no app passwords), with its own cookie scheme (`UserAuth`, path
`/client`), and registers one connection per browser login (protocol `HTTP`, `ClientSessions`), which is also the store of
the sessions. Every file action uses `IFileSystemFactory` with that connection; the page only maps the effective
permissions to its buttons (`ClientPermissionMap`, the same `PathRuleResolver` as the permission decorator).

The share links (#70) are a part of the web client (`/shares/{id}`, `ShareAccess`, `ShareApi`; the store `IShareStore` in
the settings database), off unless the web client is on and `ServerSettings.Shares` allows them. A visitor uses the file
system of the owner with the protocol `HTTPShare`: the factory limits the permissions of the owner to the scope of the
share (`ClientContext.PermissionMask`, `EffectivePermissions.Restrict`) and the events carry the share id
(`ClientContext.Metadata`). The only path rule of the share is the containment in its paths (`SharePaths`); everything
else comes from the chain. The transfers (download with ranges, zip, chunked upload) are `ClientTransfers`, the same code
as the web client.

## Several nodes

The settings database is EF Core on an `ISettingsDatabaseProvider` (#75): SQLite in `SshServer.Settings.Sql`, PostgreSQL
and SQL Server in their own projects with their own migrations (`AddPostgreSqlSettings()`, `AddSqlServerSettings()`).
`SettingsDatabase.Create` is the one place that selects one by `Settings:Provider`; every store gets its options. The
model marks the names that compare without case (`SettingsDbContext.CaseInsensitiveAnnotation`); SQLite gives them the
NOCASE collation, the PostgreSQL model rules (`PostgreSqlModelCustomizer`) make them `citext` and store the times as UTC.

With `Cluster:Enabled` (`AddSshServerCluster`, [CLUSTER.md](CLUSTER.md)) the `ClusterNodeService` of each node writes its
heartbeat and its connections (`IClusterStore`), takes the disconnect requests for its connections, syncs the bans
(`IIpBanStore`, through the `LoginBanTracker`) and polls the settings version (`ISettingsVersionStore`, raised by the
`SettingsVersionSink` for every provider event). `IClusterConnections` is what the admin UI, the REST API and the
`UserSessionCloser` use to list and close connections: on one node the registry, in a cluster the registry and
the cached connections of the other nodes. The caches (webhooks, event rules) reload on `ISettingsChangeNotifier`.
Off, everything is as on one node: no table is written and nothing polls.

The PROXY protocol (`Proxy:AllowedSources`, `ProxyProtocolOptions`) runs in the `ConnectionPreface` step of FxSsh, before
the SSH session exists, so every rule after it sees the client address of the header.

## Events

Everything that happens in the server is an `IEvent` (`SshServer.Interfaces.Events`): `FileEvent`, `AuthEvent`,
`ProviderEvent` and `SystemEvent`. Every producer publishes on the one `IEventBus` (`AddSshServerEvents()`), and
every consumer reads from it, so a new protocol gives the same events as SFTP without code in the consumers.

- **Producers.** File events come from the `EventingFileSystem` storage decorator, auth and system events from the
  protocol host (`HostedServer`), provider events from the settings repository. Events never contain secrets.
- **Sinks** (`IEventSink`) consume every event. Each sink has its own bounded queue and task: a slow or failing sink
  never delays a transfer or another sink. When a queue is full, the publisher waits (nothing is dropped) and the
  metric `freesftpsharp.events.publisher_waits` counts it.
- **Hooks** (`IEventHook`) decide synchronously whether the operation of a `Pre*` event may run
  (`IEventBus.AskAsync`). The first deny wins; the protocol answers "permission denied" and the storage is not touched.
- **Audit log.** The `AuditSink` writes every event to the `AuditEntries` table of the settings database; the
  `AuditRetentionService` removes entries older than `Audit:RetentionDays` (default 90, 0 keeps all) once a day. The
  admin UI page "Audit" and the REST API (`GET /api/v1/audit`) read it through `IAuditLog`.
- **Actor.** Every `ProviderEvent` has the actor of the change (#134): the administrator, with its API key for a REST API
  call (`AdminActor.AuditName`, "name (API key ci)"), "self" for a change of users in the web client, else "system"
  (the command line, the logins, the jobs and the event rules). The admin services that publish their own events
  (administrators, roles, webhooks, event rules, API keys) take the `AdminActor`. The settings repository is a
  singleton, so it reads the actor of the call from `AuditActorContext` (an `AsyncLocal` in one singleton, not a
  parameter of every method); `AdminScopedSettingsRepository` sets it around each change, so the admin UI and the
  REST API need no code of their own.
- **Webhooks** (#66) are the plug-in `SshServer.Webhooks` (`AddWebhooks()`), with the store `IWebhookStore` of the
  settings database. The `WebhookSink` writes one outbox row (`WebhookDeliveries`) per matching asynchronous webhook,
  and the `WebhookDispatcher` (a hosted service) sends the rows with retries; it claims a row with a lease column, so
  several nodes can share the outbox. The `WebhookEventHook` is an `IEventHook`: it asks the synchronous webhooks of a
  `Pre*` event inline, with their timeout and fail-open setting. A `HookDecision.Deny` can carry a `ClientMessage`; the
  `EventingFileSystem` puts it in the `FileSystemException`, and the protocol adds it to its "permission denied". The
  enabled webhooks are cached in memory (`WebhookCatalog`), so with no webhook an event costs no database read.
- **Event rules** (#68) are the plug-in `SshServer.EventRules` (`AddEventRules()`), with the store `IEventRuleStore` of
  the settings database. The `EventRuleSink` (rules on events) and the `EventRuleHook` (rules on `Pre*` events; the
  operation waits for them) put runs in the `EventRuleQueue`, and the `EventRuleWorker` runs them; so the event bus does
  not depend on the storage and the users that the actions need. The `EventRuleScheduler` runs the cron rules on the
  `TimeProvider`; a node claims each occurrence with a conditional update of the rule row, so it runs once on several
  nodes. The `EventRuleRunner` runs the actions in order through `IEventRuleAction` plug-ins (one class per action type,
  found by its type name; the Webhook action comes with `AddWebhooks`), never a switch on the type. The file actions use
  `IFileSystemFactory` with `ClientContext.SkipPermissions` (a server operation: no per-path permissions) and the
  protocol `EventRules`, whose events never start a rule. The enabled rules are cached in memory (`EventRuleCatalog`).
  The Command action is off unless the operator allows it; it never uses a shell. See [EVENT-RULES.md](EVENT-RULES.md).

## Observability

The core produces telemetry with `System.Diagnostics` only (`AddSshServerMetrics()`, namespace `SshServerModule.Observability`); it
has no exporter dependency and opens no port. `FreeSftpSharpMetrics` is fed from the `IConnectionRegistry` (connection gauge and
counter, one `sftp.session` activity per connection) and, as an `IEventSink`, from the event bus (logins, transfers, storage
operations, and one `storage.<operation>` activity under the session). Protocols and backends do not know about it.

Meter and activity source are both named `FreeSftpSharp`. Instruments: `freesftpsharp.connections.active` and `.connections`
{protocol}, `freesftpsharp.auth.attempts` {method,result}, `freesftpsharp.transfers` {protocol,direction,status},
`freesftpsharp.transfer.bytes`, `freesftpsharp.transfer.duration`, `freesftpsharp.storage.operation.duration`
{provider,operation}, `freesftpsharp.storage.errors` {provider,error}, and `freesftpsharp.quota.usage` (bytes) and `freesftpsharp.quota.files`
{scope} for the scopes with a disk quota (at most 1000 series). Prometheus shows them as `freesftpsharp_transfers_total` etc.

`SshServer.Observability` is the opt-in exporter project (`AddSshServerObservability(configuration)` and
`UseSshServerObservability()`, called by the web host). Everything is off until the `Observability` section says otherwise:

| Setting | Default | Effect |
|---|---|---|
| `Observability:Prometheus:Enabled` | false | `/metrics` (`Prometheus:Path`) on the web host. Needs `Prometheus:ApiKey` (bearer token) or `Prometheus:AllowedNetworks` (CIDR list); with neither, only loopback may scrape. |
| `Observability:Otlp:Endpoint` | empty | OTLP metric export to this endpoint. |
| `Observability:Otlp:Tracing` | false | Also export the traces (needs the endpoint). |
| `Observability:Health:Enabled` | false | `/healthz` (process alive, always 200) and `/readyz` (settings database readable and SSH listeners bound; 200 or 503, plain text). `?detail=true` gives JSON for the operator (same key or network rules as `/metrics`). |

The endpoints are terminal middleware at the start of the pipeline, so probes and scrapers need no login cookie and no HTTPS.
`ServerConsoleApp` calls `AddSshServerMetrics()` only: the instruments exist, nothing is exported and nothing listens.
A sample Grafana dashboard is in [grafana-dashboard.json](grafana-dashboard.json).

## Storage backends

A storage backend is a plug-in. Use this structure:

1. **One project per backend.** Examples: `SshServer.Filesystem.LocalDisk`, `SshServer.Storage.S3`,
   `SshServer.Storage.AzureBlob`. Only the backend project references the cloud SDK.
2. **One provider class per backend.** The class implements `IStorageProvider`. It has a unique name
   (for example `"s3"`), one typed options record, options validation, and a method that creates an
   `IFileSystem` from the options.
3. **One registration method per backend.** Example: `services.AddS3Storage()`. The method registers the
   provider in `IStorageProviderRegistry`. The host project (`FxSshSftpServer`, `ServerConsoleApp`) calls it.
4. **No provider switch in the core.** The core finds a provider by name through the registry. Do not
   write `switch (provider)` or `if (provider == "s3")` outside the registry.
5. **One error type.** A backend throws only `FileSystemException` with a `FileSystemError` code. It catches
   the SDK and `System.IO` exceptions and translates them.
6. **Capabilities, not type checks.** A backend tells what it can do with `StorageCapabilities`. Callers read
   the flags. They never test the backend type.
7. **One conformance suite.** Each backend adds one subclass of `FileSystemConformanceTests<TFixture>` and
   passes the full suite. A backend that fails a test must declare the missing capability instead.

A new backend changes its own project, its tests, one registration line per host, and the UI fields for its
options. If it must change other code, the abstraction is wrong. Fix the abstraction in a separate pull
request first.

## Cross-cutting rules are decorators

Permissions, path filters, quotas, bandwidth limits and events wrap an `IFileSystem` and implement
`IFileSystem` themselves.

- One decorator handles one rule.
- The storage factory (`StorageFileSystemFactory`) builds the decorator chain in one place, in a documented order.
- Protocols never repeat a rule. SFTP, WebDAV, FTP and the web client get it from the chain.
- Test each decorator alone with `InMemoryFileSystem`, and run the conformance suite through it.

The storage of a user comes from `IUserStorageResolver`: `User.Storage` (a provider name and its options as JSON, a
`StorageConfig`), or `IDefaultUserStorage` (the local disk at `User.UserRootDirectory`) for a user without one, and the
mounted virtual folders. The core decodes the options into the `IStorageProvider.OptionsType` of the provider
(`StorageOptionsCodec`) and never looks into them; the provider validates them. Option properties marked `[Secret]`
are encrypted at rest with `ISecretProtector` (ASP.NET Core data protection). The admin UI builds its fields from the
options record (`[Display]`, `[Secret]`, `[AllowedValues]`), so a backend needs no UI code of its own.

The chain today, from the backend outwards:

0. `DiskQuotaFileSystem` (#62), around each storage with a disk quota (the own storage of the user, and each virtual
   folder): one storage is one quota scope (see "Quotas and bandwidth"). Left out for a storage without a quota.
1. `MountedFileSystem` (#56), added by the factory for a user with virtual folders: routes each path to the storage
   with the longest mount path. A mount point is the root of its storage (it cannot be removed or renamed), and a rename
   between two storages throws `OpNotSupported`. Every rule above it sees the virtual paths.
2. `TransferQuotaFileSystem` and `BandwidthFileSystem` (#62), around the whole session: the transfer quota and the
   bandwidth of the user for this client. Each is left out without its limit, and both for a server operation
   (`ClientContext.SkipPermissions`). Inside the permissions, so a refused operation is not counted.
3. `PermissionFileSystem` (#59), added by the factory: per-path permissions and path filters, limited to
   `ClientContext.PermissionMask` when the client has one (the scope of a share link, #70). It throws only
   `PermissionDenied` (and `NoSuchFile` for a hidden name); a refused operation never reaches the backend. The
   factory leaves it out for a user who may do everything, and for a server operation (`ClientContext.SkipPermissions`,
   the actions of the event rules; a protocol never sets it). It compares paths like the backend does
   (`StorageCapabilities.CaseInsensitivePaths`), so another spelling of a directory gets the same rules.
4. `EventingFileSystem` (#65): the file events of the client (see "Events"). It is outside the permissions, so an
   operation that the permissions refuse still gives an event (status `Error`) in the audit log, and the `Pre*`
   hooks are asked before the permissions. A hook deny never reaches the permissions or the backend.
5. `ConnectionTrackingFileSystem` (#57): the activity and open files of the connection (see "Connections"), for a
   client with a connection id in its `ClientContext`. Outermost, so every request is activity, also a refused one.

All of them are added by the factory; the protocol passes a `ClientContext` (protocol, client address, connection id)
to `IFileSystemFactory.CreateAsync`.

The settings of a user come from `IEffectiveUserSettingsService` (`SshServer.Interfaces.Users`), the one place that
resolves them with the groups (#61): the user's own value, else the primary group, else the secondary groups in order,
else the server default. The permission decorator, the storage resolver (storage template with `%username%`, the virtual
folders of the groups) and the login (methods, allowed networks) read them from there. No protocol and no backend
reads `User.Permissions`, `User.Storage` or a `Group` itself; a new shared setting is one more nullable property on
`Group` and one more line in that service.

The lifecycle of a login (status, expiry, password age, session limit; #61) is in `UserLoginRules`. Every protocol asks
it before the credential check and refuses like a wrong credential; the session limit is checked again when the login is
recorded (`IConnectionRegistry.TrySetAuthenticated`, one step with the count), so two logins at the same time cannot
both take the last session. The `UserSessionCloser` (registered by `AddSshServerConnections()`) is the one place that closes the sessions of a user
whose account ended (#132), in every protocol through the registry, with a reason ("The account expired.", "The account
was disabled.", "The account was removed.") that is logged and published as a `System.SessionsClosed` event (audit log). As
an event sink it closes the sessions of a user that is disabled or removed, from the provider events. An expiry is a
point in time and no event, so the `UserLifecycleService` (every 5 seconds) checks the users of the open connections and
calls the closer for an expired one.

## Authentication providers

The credential of a login (password, public key) is checked by the `IAuthenticationProvider`s (#64,
`SshServer.Interfaces.Authentication`) through one service, `IUserAuthenticator` (`UserAuthenticator`,
`AddSshServerAuthentication()`). The built-in `DatabaseAuthenticationProvider` checks the stored hash and keys; the
plug-ins `SshServer.Authentication.Http` (`AddHttpAuthHook()`) and `SshServer.Authentication.Ldap`
(`AddLdapAuthentication()`) register only when their section is configured. The core never knows a provider type.

- **Chain.** The providers run in the order of `Auth:Providers` (default: the database, then the plug-ins); the first
  success or failure wins, "not handled" asks the next one. An exception of a provider is a failure (fail closed).
- **Ownership.** `User.AuthenticationProvider` (null: the database) names the one provider that checks a stored user.
  A `CredentialOwner` registration (#145) narrows it: an owner that owns only the password (the OpenID Connect sign-in,
  `oidc`) leaves the SSH public keys to the database provider. App passwords are local for every owner.
- **Just in time.** A provider can return an `ExternalUser` (groups by name, permissions, networks, session limit). Its
  JSON form is `UserAttributes` (#136), with the names and types of the REST API user; the HTTP hook answers with it. The
  `ExternalUserProvisioner` makes the user in memory; the protocol checks it like a stored user and calls
  `IUserAuthenticator.Save` when the login is verified (SSH: after the signature of a public key). The status and the
  expiry stay local.
- **Every protocol** does the same steps: read the stored user, check `UserLoginRules` and the effective settings
  (refusal: `SpendFailureTimeAsync`, the time of a wrong password), `VerifyAsync`, check again with a returned user,
  `Save`. `HostedServer` does it for SSH, `PasswordLoginService` for WebDAV, the web client and the later password protocols.

## Quotas and bandwidth

The limits of a user (#62) are `User.DiskQuota` (bytes and files of the own storage, "/" without the virtual folders),
`VirtualFolderMount.Quota` (the same per mounted folder), `User.TransferQuota` (uploaded, downloaded and total bytes until a
reset) and `User.Bandwidth` (KiB/s per session and direction, with overrides per client network). `IEffectiveQuotaService`
takes them from `IEffectiveUserSettingsService` (the user, else its primary group, else its secondary groups, #61; a mount brings its own quota). 0 or null is unlimited, and a user
without a limit gets no quota decorator and no counter at all.

- **Counters.** `QuotaUsageTracker` keeps the counters of each `QuotaScope` ("user:name" or "folder:id"; a folder is one
  scope for every user that mounts it) in memory. The decorators check and change them without a database call; every
  few seconds (`QuotaUsageFlushService`) the changes are written to the shared `IQuotaUsageStore` as increments (table
  `QuotaUsages`; in memory with the LiteDB settings), and the write gives back the stored value with the changes of other
  nodes. The storage is never scanned for a write.
- **Disk quota.** A new file reserves a file, a full quota refuses to create one, and every write that makes a file larger
  reserves the growth first, so one large write cannot go over the limit. A refused write gives `QuotaExceeded` (SFTP:
  `SSH_FX_FAILURE` "Quota exceeded: path"); the handle is aborted in the storage at once and the partial file is removed, so
  the counters do not drift. Delete, a replacing rename and a SETSTAT size change are counted; a lost session counts what
  the storage kept. `statvfs` reports the quota as the size of the storage.
- **Scan.** `QuotaScanService` (a hosted service, `QuotaScanQueue`) recomputes the disk usage of a scope from its storage
  (`ListAsync` recursion, without the mount paths for the own storage), one request after the other: for a scope that was
  never scanned at its first session, after a change of the quota or storage of a user (`QuotaProviderEventSink`, from the
  provider events), from the "Rescan quota" button, the event rule action "QuotaScan", and every `Quota:ScanIntervalHours`
  (default 24, 0 off) for every scope with a quota. A removed user or folder loses its counters.
- **Transfer quota.** A write over the upload or total limit fails with `QuotaExceeded`; a read gets at most what is left.
  The admin UI ("Reset transfer counters") and the event rule action "QuotaResetTransfer" set the counters to 0.
- **Bandwidth.** A `TokenBucket` per session and direction (capacity a quarter of a second, debt for larger requests, on a
  `TimeProvider`): a write waits before it reaches the storage, a read waits before it returns, so the protocol answers
  later and SFTP clients slow down to the rate.

## Administrators and authorization

The administrators and the scope roles are in the settings database (`IAdminStore`, `SshServer.Interfaces.Admins`).
`AdminAdministrationService` is the one place for their rules (validation, no privilege escalation, provider events with
the actor); the admin UI and the command line (`--create-admin`) use it.

- **Permissions are policies.** Each `AdminPermissions` flag is an ASP.NET Core authorization policy with the same name
  (`AdminPolicies`). Every page has `[Authorize(Policy = ...)]`; the endpoint checks it for the first request and
  `AuthorizeRouteView` for the navigation in the circuit. The REST API (#67) uses the same policies.
- **Services check again.** The pages do not use the shared singletons for admin work: they use scoped views of them
  (`AdminScopedSettingsRepository`, `ScopedConnections`, `ScopedAuditLog`) that check the permission and the scope of
  the signed-in administrator (`CurrentAdmin`) themselves. A hidden button is never the only check.
- **The scope is applied in one place.** A scoped administrator sees only the users and groups of its role; the scoped
  views filter by it, so the users, groups, connections and audit entries of another role are "not found". It adds or
  removes only the groups of its role for its users.
- **The login cookie is checked against the database.** It has a stamp of the security fields; the cookie handler (each
  request) and `AdminRevalidatingAuthenticationStateProvider` (each circuit) reject it when the administrator changed.
- **Single sign-on.** The OpenID Connect sign-in (#73, `FxSshSftpServer/Security/Oidc`, `AddOidcSignIn()`, see
  [OIDC.md](OIDC.md)) registers one handler per configured area (`OidcAdmin` for the admin UI, `OidcClient` for the web
  client), with its own callback path. Each handler signs in to the local cookie scheme of its area with a local
  principal (no tokens), so it never opens the other area. The account check is `AdminOidcAccounts` and
  `ClientOidcAccounts`; the new users of the web client come from the `ExternalUserProvisioner` of the authentication
  providers (#64) with the provider name `oidc`. The administrators that the sign-in creates have the same owner
  (`Admin.AuthenticationProvider`, #145): `AdminAdministrationService` and `AdminCredentialValidator` refuse a local
  password for them. The back-channel logout of the provider (`OidcBackChannelLogout`, #145) checks the logout token
  (`OidcLogoutTokenValidator`) and ends the sessions of the provider session: in `ClientSessions` for the web client,
  through `AdminOidcLogouts` (per node, in memory; checked with the cookie and the circuit) for the admin UI. Nothing is
  registered without configuration.
- **One application layer for the UI and the API.** The claims, the policies, `CurrentAdmin` and the scoped views are in
  `SshServer.Administration`; the admin UI (`FxSshSftpServer`) and the REST API (`SshServer.Api`) both reference it.

## REST API

`SshServer.Api` (#67, [REST-API.md](REST-API.md)) is the REST API v1 under `/api/v1`: minimal API endpoints, the OpenAPI
document of `Microsoft.AspNetCore.OpenApi` at `/api/v1/openapi.json` (committed as [openapi.json](openapi.json) and
compared by a test), and two authentication schemes behind one policy scheme: a bearer token (JWT) from
`POST /api/v1/token`, and an API key (`X-API-Key`, `IApiKeyStore`, only the SHA-256 hash stored). The web host calls
`AddRestApi()` and `MapRestApi()`; nothing is mapped until `Api:Enabled` is true.

- **No second permission model.** Each route has the policy of its `AdminPermissions` flag, and the endpoints call the
  same scoped services as the pages (`AdminScopedSettingsRepository`, `ScopedConnections`, `ScopedAuditLog`,
  `UserAdministrationService`, `VirtualFolderService`, `GroupService`, `AdminAdministrationService`, `WebhookAdministrationService`,
  `EventRuleAdministrationService`). An
  endpoint filter gives the principal of the request to the authentication state, so `CurrentAdmin` and the services
  check the API caller like the administrator of a circuit. A token or key has the claims of the login cookie, checked
  against the stored administrator on each request; an API key is the permissions of its owner masked with its scopes.
- **Secrets are write-only.** The views have whether a secret is set, never its value. The dump has them only
  encrypted with a passphrase of the caller (`StorageConfigService.Export`/`Import`).
- **One error form.** The exceptions of the services become RFC 9457 problem details in one endpoint filter.

## Two-factor authentication

The TOTP second factor (#63) is the plug-in `SshServer.TwoFactor` (`AddTwoFactor(configuration)`, settings `Auth:Totp`).
The protocols and the admin login know only `ITwoFactorVerifier` (`SshServer.Interfaces.TwoFactor`); the algorithm
(`Totp`, RFC 6238) is a pure function there too. `TwoFactorService` is the one place for the rules: setup confirmed with
a code, replay protection, recovery codes, the per-account limit for wrong codes and the reset. The enrolments are in
the settings database (`ITwoFactorStore`, table TwoFactorEnrolments, removed with the user or administrator); the
store compares a version, so one code cannot log in twice, also on two nodes. The secrets are encrypted with the data
protection key ring of the host, like the webhook secrets.

- **SSH.** Keyboard-interactive (RFC 4256, a local FxSsh patch) is a login method. `AuthenticationProgress` adds the code
  step after the configured steps of a user with TOTP, so the server answers them with partial success and asks for the
  code. A keyboard-interactive step asks for the code with TOTP and for the password without.
- **Admin UI.** After the right password, `Login` sets a short encrypted cookie (`PendingTwoFactorLogin`) and `LoginCode`
  issues the login cookie only after a valid code. `TwoFactorAdministration` (scoped) checks the permissions and the
  scope of the signed-in administrator for every setup and reset; the pages use only it.

## General rules

- **Dependencies point inwards.** `SshServer.Interfaces` references no other project and no SDK. Backends
  and hosts reference the interfaces, never the other way round.
- **Constructor injection only.** Do not use static mutable state, a service locator, or `new` for services.
- **Small classes with one task.** If a class has more than one reason to change, split it.
- **Typed options.** Use one options record per component, bind it from configuration, and validate it at
  start (`IValidateOptions<T>`). Mark secrets so that the UI, the API and the logs never show them.
- **Application services between the UI and the core.** Blazor pages and the REST API (#67) call the same
  services. A page does not use the database or a backend directly.
- **Asynchronous I/O.** Storage, authentication and event code is `async` and takes a `CancellationToken`.
- **No dead code.** Remove code that nothing uses. Do not keep compatibility shims after a migration.
