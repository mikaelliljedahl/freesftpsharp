# FreeSftpSharp technical roadmap

This document describes where the server is going and in which order. Every item links to a GitHub issue
that holds the design, the scope, the acceptance criteria and the test approach. The issues are grouped in
[milestones](https://github.com/mikaelliljedahl/freesftpsharp/milestones) M1 to M6 and carry the `roadmap`
label; the umbrella issues per milestone carry `epic`. The order inside a milestone is a suggestion, the
dependencies are not.

## Vision

FreeSftpSharp is to become a complete, self-hosted managed file transfer server on .NET: one set of users,
permissions, quotas and events exposed over SFTP, HTTPS (web client and REST API), WebDAV and FTP/S, with
files on local disk (plain or encrypted), S3-compatible storage, Azure Blob Storage or Google Cloud Storage.
It should run as one process on a laptop with SQLite, and as several stateless nodes on a shared database
behind a load balancer, and be a solid core for anyone who hosts file transfer for many users or tenants.
Feature parity with the leading open-source servers in this space (for example SFTPGo) is the yardstick.

## Architecture principles

The binding rules for the code structure are in [ARCHITECTURE.md](ARCHITECTURE.md). The first rule: the
server stays a zero-configuration local test server by default, and every new feature is opt-in.

1. **One storage abstraction.** Every backend implements the asynchronous, handle-based `IFileSystem`
   (`SshServer.Interfaces`) and is created by `IFileSystemFactory`. Backends never leak SDK or `System.IO`
   exceptions; they throw `FileSystemException` with an error code that protocols map 1:1. One conformance
   test suite runs against every backend (#51).
2. **Cross-cutting rules are decorators.** Permissions, path filters, quotas, bandwidth and events are
   `IFileSystem` decorators stacked by the factory, so every protocol gets the same enforcement for free and
   nothing is implemented twice (#59, #62, #65).
3. **One authentication chain.** `IAuthenticationProvider` implementations (database, external HTTP, LDAP,
   later more) run in order; SSH, HTTPS, WebDAV and FTP call the same chain (#64).
4. **Everything is an event.** File, authentication, provider and system events go through one `IEventBus`
   that feeds the audit log, webhooks, event rules and metrics; `Pre*` events can refuse an operation (#65).
5. **The REST API is the control plane.** The Blazor admin UI and the API call the same application
   services, so every operation is scriptable and documented in OpenAPI (#67).
6. **Stateless nodes, shared database.** No node-local state that matters: bans, quota counters, outboxes,
   leases, signing and data protection keys live in the database, so nodes can be added or replaced (#75).
7. **Secure by default.** Modern SSH algorithms only, salted PBKDF2 hashes, no plaintext secrets in the
   database or in logs, fail-closed hooks, HTTPS required for anything that carries credentials, commands
   disabled unless enabled, least privilege for administrators.
8. **Upstream first.** SSH protocol work goes into `external/FxSsh` and is offered upstream as pull
   requests; the server adds policy, storage and management on top.
9. **Tests with the code.** Protocol and security behaviour is written test-first (see
   [AGENTS.md](../AGENTS.md)); storage backends are tested against emulators (MinIO, Azurite,
   fake-gcs-server) on the Ubuntu CI job and against fakes everywhere else.

## Milestones

### M1 Foundation: finish the current work

Done when the server runs on the upstream SFTP engine, the admin UI has no third-party component library,
and everything an operator needs is configurable without the UI.

| Item | Issue | Depends on | Done when |
|---|---|---|---|
| SFTP on the upstream FxSsh `SftpService` with an adapter over our file system | #40 | FxSsh subtree (done, #47) | `SftpSubsystem` removed, e2e tests green with SSH.NET and OpenSSH |
| Admin UI refresh: Bootstrap 5 and built-in Blazor components, no Radzen | #42 | | All pages work without Radzen; Blazor Web App model |
| Listen port and bind addresses from configuration | #26 (PR #49) | | `ServerConsoleApp --port 2222` works without touching the database |
| Serilog configuration in `appsettings.json`, clean log levels | #33 (PR #50) | | A normal start writes no warnings |
| Global IP blacklist, auto-ban and `BindToAddress` | #43 | | Closed |
| Symbolic links cannot escape the user root | #25 | #40 | Link outside the root gives `SSH_FX_PERMISSION_DENIED` |
| Obsolete API and analyzer warnings, NuGet lock files | #34, #32 | | Clean build, reproducible restore |
| OpenSSH SFTP extensions; legacy Windows client workaround | #2, #28 | #40 | Decided and implemented or closed |

### M2 Storage backends ([epic #77](https://github.com/mikaelliljedahl/freesftpsharp/issues/77))

Done when a user root can live on any supported backend, several locations can be mounted into one root,
and the conformance suite passes for every backend in CI.

| Item | Issue | Depends on |
|---|---|---|
| Async, handle-based storage abstraction, `InMemoryFileSystem`, conformance test suite | #51 | #40 |
| Encrypted local filesystem: AES-256-GCM per 64 KiB chunk, per-file HKDF keys, key rotation | #52 | #51 |
| S3-compatible backend (`AWSSDK.S3`, multipart upload, range reads; MinIO in CI) | #53 | #51 |
| Azure Blob Storage backend (`Azure.Storage.Blobs`, block upload; Azurite in CI) | #54 | #51, helpers from #53 |
| Google Cloud Storage backend (`Google.Cloud.Storage.V1`, resumable upload; fake-gcs-server in CI) | #55 | #51, helpers from #53 |
| Per-user storage configuration, virtual folders and mount points, provider registry | #56 | #51, one non-local backend |

### M3 Auth & access control ([epic #78](https://github.com/mikaelliljedahl/freesftpsharp/issues/78))

Done when a user can be authenticated in several ways, restricted per path and by quota, managed in groups,
and the server has several administrators with roles.

| Item | Issue | Depends on |
|---|---|---|
| Session registry: active connections, live transfers, forced disconnect | #57 | #42 |
| Multiple public keys per user, allowed auth methods, multi-step auth (partial success in FxSsh) | #58 | |
| Per-path permissions (list, download, upload, overwrite, delete, rename, ...) and path filters | #59 | #51 |
| Administrator accounts in the database, roles, scoped administration | #60 | #42 |
| Groups with inherited settings; user status, expiry, session limit, password age | #61 | #59, #57 |
| Disk quotas, transfer quotas and per-session bandwidth limits | #62 | #51, #56, #57 |
| TOTP second factor over `keyboard-interactive` (added to FxSsh) and in the web UI | #63 | #58, #60 |
| Pluggable authentication providers: external HTTP hook and LDAP | #64 | #58, #61 |

### M4 Events, hooks & API ([epic #79](https://github.com/mikaelliljedahl/freesftpsharp/issues/79))

Done when every action produces an event that reaches the audit log, webhooks and rules, and every
administrative operation is available through a documented REST API.

| Item | Issue | Depends on |
|---|---|---|
| Event model, `IEventBus`, eventing decorator, audit log table and page, retention | #65 | #51, #57 |
| Webhooks: signed JSON payloads, outbox with retries, synchronous `Pre*` hooks | #66 | #65 |
| REST API v1 with OpenAPI, admin JWT and API keys, dump and load | #67 | #60 |
| Event rules and actions: email, command, file operations, retention, schedules | #68 | #65, #66 |

### M5 Protocols & web client ([epic #80](https://github.com/mikaelliljedahl/freesftpsharp/issues/80))

Done when the same users and storage are reachable from a browser, WebDAV and FTP/S with the same rules
and events, and the web UIs support single sign-on.

| Item | Issue | Depends on |
|---|---|---|
| End-user web client: browse, chunked upload, streaming download, account self-service | #69 | #42, #51, #59, #62 |
| Share links: public download and upload links with password, expiry and limits | #70 | #69 |
| WebDAV server (class 1 and 2, Litmus in CI), app passwords, per-protocol flags | #71 | #51, #59, #62, #65 |
| FTP and FTPS server (explicit TLS, passive mode, MLSD) | #72 | #71 |
| OpenID Connect sign-in for administrators and users | #73 | #60, #69 |
| OpenSSH SFTP extensions, SCP subsystem | #2, later | #40 |

### M6 Operations & scale

Done when several nodes run on one database, the server exposes metrics and health, and a release is a
container image plus archives produced by CI.

| Item | Issue | Depends on |
|---|---|---|
| Metrics, tracing and health endpoints (OpenTelemetry, Prometheus) | #74 | #57, #65 |
| Multi-node: PostgreSQL and SQL Server providers, shared state, settings cache, proxy protocol | #75 | #43, #57, #66, #68, #67 |
| Container image (GHCR, multi-arch), release workflow, compose examples, first-run bootstrap | #76 | #26, #33, #74 |

## Later and not planned

- SSH user certificates and SCP depend on upstream FxSsh support and will get issues when the engine is ready.
- Key management services (Azure Key Vault, AWS KMS, Google Cloud KMS) plug into `IMasterKeyProvider` from #52.
- Geo-IP filtering, ACME certificates for HTTPS and FTPS, SFTP-as-backend (chaining to another SFTP server),
  a CLI over the REST API and a Helm chart are candidates once the milestones above are done.
- Antivirus or content scanning is best done by a synchronous `PreUpload` webhook (#66) to an external
  scanner; no scanner is planned inside the server.

## How to contribute to the roadmap

Pick an issue in the lowest open milestone, comment that you take it, and follow [AGENTS.md](../AGENTS.md).
Proposals for new items are welcome as issues; please state the problem, a design sketch, and how it would
be tested.
