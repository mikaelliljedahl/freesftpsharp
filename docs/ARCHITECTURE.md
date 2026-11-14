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
| Settings store | `ISettingsRepository` | SQLite, later PostgreSQL and SQL Server | #13, #75 |
| Protocol | hosted service over the shared services | SFTP, WebDAV, FTP/S, HTTPS | #71, #72 |

## Connections

Every protocol registers its open connections in the `IConnectionRegistry` singleton (`SshServer.Interfaces.Connections`,
`AddSshServerConnections()`): it registers at accept, sets the user after the login, unregisters on close, and gives a
callback that closes the connection, so `DisconnectAsync` works for every protocol. The registry gives each connection
a stable `ConnectionInfo.Id` (a GUID) for the whole connection; later features (session limits, events, metrics) use it.
The registry is in memory and per node.

The `ConnectionTrackingFileSystem` decorator keeps the registry entry up to date (last activity, open files with their
byte counts). The protocol passes the connection id in the `ClientContext` of `IFileSystemFactory.CreateAsync`, and the
factory adds the decorator to its chain.

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
  admin UI page "Audit" and later the REST API read it through `IAuditLog`.
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
{provider,operation} and `freesftpsharp.storage.errors` {provider,error}. Prometheus shows them as `freesftpsharp_transfers_total` etc.

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

0. `MountedFileSystem` (#56), added by the factory for a user with virtual folders: routes each path to the storage
   with the longest mount path. A mount point is the root of its storage (it cannot be removed or renamed), and a rename
   between two storages throws `OpNotSupported`. It is innermost, so every rule below sees the virtual paths.
1. `PermissionFileSystem` (#59), added by the factory: per-path permissions and path filters. It throws only
   `PermissionDenied` (and `NoSuchFile` for a hidden name); a refused operation never reaches the backend. The
   factory leaves it out for a user who may do everything, and for a server operation (`ClientContext.SkipPermissions`,
   the actions of the event rules; a protocol never sets it). It compares paths like the backend does
   (`StorageCapabilities.CaseInsensitivePaths`), so another spelling of a directory gets the same rules.
2. `EventingFileSystem` (#65): the file events of the client (see "Events"). It is outside the permissions, so an
   operation that the permissions refuse still gives an event (status `Error`) in the audit log, and the `Pre*`
   hooks are asked before the permissions. A hook deny never reaches the permissions or the backend.
3. `ConnectionTrackingFileSystem` (#57): the activity and open files of the connection (see "Connections"), for a
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
both take the last session. The `DisabledUserDisconnector` sink (registered by `AddSshServerConnections()`) closes the
connections of a user that is disabled or removed, from the provider events, through the registry.

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
