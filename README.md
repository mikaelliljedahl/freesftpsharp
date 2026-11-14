
# SftpServer (SSHServer)

Sftp Server implementation based on SSHServer library based heavily on [FxSsh](https://github.com/Aimeast/FxSsh). This fork (based on https://github.com/0xFireball/SSHServer) implements the sftp subsystem and a Graphical user interface for administration of users and server settings.

## Current status

The M1 Foundation milestone of the [technical roadmap](docs/ROADMAP.md) is done:

- SFTP version 3 with all file and directory operations, and the common OpenSSH extensions. Symbolic links are
  not supported.
- Each user is locked to a root directory. Path traversal and links that point outside the root are refused.
- Password (salted PBKDF2) and public key login (several ed25519, ECDSA and RSA keys per user), allowed login methods
  and multi-step login (key and password) per user, IP filters and auto-ban.
- A Blazor admin UI and a `user` command line for users and settings, stored in SQLite.
- A storage abstraction (`IFileSystem`) with the local disk as the first backend. Other backends are plug-ins,
  see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- An automated test suite: unit tests, and end-to-end tests with SSH.NET and OpenSSH `sftp`. CI runs it on
  Ubuntu and Windows.

The next milestones (M2 to M6) add storage backends, access control, events and an API, more protocols, and
operations support. The server still starts with no configuration, as a simple local test server, and each new
feature is opt-in. You are welcome to create pull requests.

## Quick start (local test server)

From a download to an SFTP login, with no configuration file:

```sh
# 1. Add a user. The root directory is created if it does not exist. The password is read from stdin
#    (or asked for without echo on a terminal), never from an argument.
echo "a-password" | ServerConsoleApp user add alice --root ./alice-files --password-stdin

# 2. Start the server (port 22; add --port 2222 to use another port).
ServerConsoleApp --port 2222
```

Then connect: `sftp -P 2222 alice@localhost`. The server reads users from the database at every login, so you can
add users while it runs.

`user add` and the other `user` commands use the same settings database as the server start (the SQLite file
`freesftpsharp.db` next to the app, or what `ConnectionStrings:Settings` says), do their work and exit. They do not
start the server. The rules are the same as in the admin UI (the same service): the user name has no spaces, `:`,
`/` or `\`, a user name is unique in any letter case, and a password has at least 8 characters.

| Command | What it does |
| --- | --- |
| `ServerConsoleApp user add <name> --root <dir> [--password-stdin \| --public-key <file>]` | Adds a user. `--public-key` takes an OpenSSH `.pub` or `authorized_keys` file (ed25519, ECDSA or RSA keys of at least 2048 bits, one per line) or a PEM public key. Lines with options (`from=`, `restrict`, ...) are refused. Without either option on a terminal, it asks for the password twice. |
| `ServerConsoleApp user list` | Lists the users: name, login kind (`password`, `key` or `N keys`, and `(all of publickey,password)` for a multi-step login) and root directory. It never shows hashes or keys. |
| `ServerConsoleApp user remove <name>` | Removes a user. The files in the root directory are not deleted. |

Exit codes: 0 = done, 1 = the operation failed (the reason is on stderr), 2 = wrong arguments (the usage is on stderr).

## Run in a container

```sh
docker run -p 2222:22 -p 8080:80 -v freesftpsharp-data:/data ghcr.io/mikaelliljedahl/freesftpsharp
```

The first start prints a generated admin password to the log. Log in at `http://localhost:8080`, add a user, then
`sftp -P 2222 alice@localhost`. Releases also have self-contained archives (`--version` prints the version). See
[docs/deployment.md](docs/deployment.md) for compose, systemd and Kubernetes examples, HTTPS, upgrade and backup.

## Admin web UI (FxSshSftpServer)

`FxSshSftpServer` hosts the SSH/SFTP server and a Blazor admin UI for the server settings and the SFTP users.
The UI has its own administrator accounts with permissions and optional scope roles (see
[Administrators, permissions and roles](#administrators-permissions-and-roles)). They are separate from the SFTP users.

The UI is a Blazor Web App (interactive server rendering) with Bootstrap 5.3 and Bootstrap Icons. All CSS, fonts and
scripts are local files in `wwwroot/lib`, so the UI needs no internet access. It has these pages:

| Page | What it shows and changes |
| --- | --- |
| Dashboard (`/`) | The effective listen port and bind addresses (and whether they come from the configuration or the database), the number of users, the active bans, the host key fingerprints |
| Users (`/users`) | A searchable user list; add, edit and delete (with a confirmation) users: root directory (with a warning when it does not exist), password (salted PBKDF2), the public keys (a list with type, SHA256 fingerprint, comment, added and expiry date; add keys from pasted `authorized_keys` text with an optional expiry, generate an ed25519 or RSA 4096 key pair (the browser downloads the private key once), remove a key with a confirmation), the allowed login methods and the multi-step login, the per-user IP whitelist (CIDR, validated), the last successful login |
| Server settings (`/general`) | Listen port and bind addresses (with a note when `SshServer:Port` / `SshServer:BindToAddress` override them), server banner, idle timeout, `EnableCommand`, `EnableDirectTcpIp` (with a security warning), the host key fingerprints (never the private keys) and the algorithms the server offers |
| Connections (`/connections`) | The open client connections (user, client address, protocol and client version, connected since, last activity) with the files they read or write now and the bytes so far, refreshed every 2 seconds; a "Disconnect" action with a confirmation |
| IP access and bans (`/access`) | The global blacklist, the global whitelist mode and list (CIDR, validated), the auto-ban settings, and the active bans with an "Unban" action |
| Audit (`/audit`) | The audit log: uploads, downloads, deletes, renames, directories, logins and failed logins, bans, changes of users and settings, with user, client address, path, size, duration and status; filters (user, type, status, date range) and a CSV export |
| Webhooks (`/webhooks`) | The webhooks: add, edit and delete (URL, method, secret, static headers, events, user and path filters, synchronous or not, fail open, timeout); "Send test event"; the deliveries of each webhook with status, attempts and the start of the answer, and "Redeliver" |
| Event rules (`/eventrules`) | The event rules: add, edit and delete (trigger on events, a cron schedule or on demand; user, path, protocol, size and result conditions; an ordered list of actions with stop on failure and failure actions); "Run now"; the execution history of each rule |
| Admins (`/admins`) | The administrators: add, edit and delete; permissions, scope role, allowed networks, enabled, "must change the password at the next login" |
| Roles (`/roles`) | The scope roles: add and delete roles, and add users to a role or remove them |
| Change password (`/ChangePassword`) | The signed-in administrator sets a new password (with the current one) |

The UI has a dark mode (the half-circle button in the top bar; it follows the OS by default) and works on phone widths.

### The first administrator

The administrators are stored in the settings database. There are two ways to create the first one:

- **On the command line** (new installations): `FxSshSftpServer --create-admin <name>` creates a super admin in the
  same database as the server (same configuration) and exits. It asks for the password twice, or reads one line from
  stdin when the input is redirected (`echo "..." | FxSshSftpServer --create-admin alice`). Then start the server.
- **From the configuration** (`AdminAuth`, as in older versions): when the database has no administrator yet, the
  configured `AdminAuth:UserName` / `AdminAuth:PasswordHash` account is imported **once** as a super admin at the
  start, and the log says so. An existing installation therefore keeps its login after the upgrade.
  After the import the stored administrators are used; a later change of `AdminAuth:UserName` or
  `AdminAuth:PasswordHash` is ignored (the log says so). Change the password on the "Change password" page instead.

To set the configured account:

1. Create a password hash (salted PBKDF2-SHA256, 600,000 iterations). The command asks for the password twice
   and prints the configuration value; the password itself is not stored or printed:

   ```sh
   dotnet run --project FxSshSftpServer -- --hash-admin-password
   # or, for a published build:
   FxSshSftpServer --hash-admin-password
   ```

   It also reads one line from stdin when the input is redirected (`echo "..." | FxSshSftpServer --hash-admin-password`).

2. Put the user name and the hash in the configuration. Use one of these (do not commit a hash to the repository):

   - Environment variables: `AdminAuth__UserName=admin` and `AdminAuth__PasswordHash=PBKDF2-SHA256.600000....`
   - User secrets (development): `dotnet user-secrets --project FxSshSftpServer set "AdminAuth:PasswordHash" "PBKDF2-SHA256.600000...."`
   - `appsettings.json` / `appsettings.Production.json` next to the executable:
     `"AdminAuth": { "UserName": "admin", "PasswordHash": "PBKDF2-SHA256.600000...." }`

3. Restart the server. A plaintext password in `AdminAuth:PasswordHash` is not accepted.

If no administrator is stored and no valid admin credential is configured, the UI is closed: every request gets
`503 Service Unavailable` with a short help text, and the log has an error that tells what is missing. The SSH server
still runs.

All pages and the Blazor hub (`/_blazor`) need a login (cookie authentication, fallback authorization policy), and
each page needs the permission of its policy (see below).

### Administrators, permissions and roles

Each administrator has a set of permissions. Each permission is an ASP.NET Core authorization policy with the same
name; a page that needs a permission answers `403 Forbidden` without it, and the menu shows only the pages the
administrator may open. The services behind the pages check the same permissions again, so a missing permission is
refused on the server also for a direct call.

| Permission | What it allows |
| --- | --- |
| `SuperAdmin` | Everything, also every other permission |
| `ManageUsers` | The Users page: add, change and delete SFTP users |
| `ManageEvents` | The Webhooks and Event rules pages |
| `ManageGroups`, `ManageFolders` | Reserved for groups and virtual folders (later roadmap items) |
| `ViewConnections` | The Connections page |
| `DisconnectConnections` | The "Disconnect" action on the Connections page |
| `ViewAudit` | The Audit page |
| `ManageSettings` | The Server settings and IP access and bans pages |
| `ManageAdmins` | The Admins and Roles pages |

Rules:

- An administrator never grants a permission that it does not have, and it cannot change or delete an administrator
  that has more permissions than itself. So only a super admin creates or changes super admins.
- Nobody changes its own permissions, status or scope, or deletes itself, so the last super admin always stays.
- A change of the password, the permissions, the scope, the status or the allowed networks of an administrator ends
  its other sessions at the next request (an open page within 30 seconds).
- "Allowed networks" (CIDR, like the user whitelist) limit the addresses an administrator may log in from.
- An administrator with "must change the password" gets the Change password page after the login and has no
  permission until it has set a new password.

**Scope roles** separate tenants inside one server (like the roles of SFTPGo). Create a role on the Roles page and add
users to it. An administrator with a role as its *scope*:

- sees and manages only the users of the role (another user is "not found", also by its name),
- creates users that always get the role, and cannot move a user to another role,
- sees and closes only the connections of these users, and reads only their audit entries,
- can only have the permissions `ManageUsers`, `ManageGroups`, `ManageFolders`, `ViewConnections`,
  `DisconnectConnections` and `ViewAudit`: the server settings and the administrators are global.

An administrator without a scope sees every user. A role that users or administrators have cannot be deleted.

Admin logins (also failed ones) and every change of an administrator or a role are in the audit log, with the
administrator that made the change. Admin passwords are salted PBKDF2-SHA256 hashes, like the SFTP user passwords.
With the obsolete LiteDB settings provider the administrators are kept in memory only (the configured account is
imported at every start).

The login cookie, the antiforgery tokens and the secrets of the storage configurations are protected with ASP.NET Core data protection keys. The keys are
stored in `DataProtection:KeysPath` (default: `keys/` in the app directory), so a login survives a restart. On
Windows the keys are encrypted with DPAPI. On Linux and macOS they are stored unencrypted, and the log has a
warning about it at the first start: give the directory restrictive file permissions (for example `chmod 700`).
The login form has an antiforgery token. After 5 failed logins from one IP address, that address is locked out
for 15 minutes (`AdminAuth:MaxFailedLogins`, `AdminAuth:LockoutMinutes`). Use "Log out" in the menu to end the
session; a session expires after 8 hours without use.

### Expose the UI

By default the UI listens only on `http://localhost:5000` (`Kestrel:Endpoints:Http:Url` in `appsettings.json`).
To reach it from another machine, prefer an SSH tunnel (`ssh -L 5000:localhost:5000 server`) or a reverse proxy
with HTTPS on the same host. If you must bind Kestrel to another address, use HTTPS, because the login and the
session cookie are otherwise sent in clear text, for example:

```sh
Kestrel__Endpoints__Https__Url=https://0.0.0.0:5001
Kestrel__Endpoints__Https__Certificate__Path=/path/cert.pfx
Kestrel__Endpoints__Https__Certificate__Password=...
```

### SFTP user passwords

SFTP user passwords are stored with the same salted PBKDF2-SHA256 hash as the admin password (600,000 iterations).
Older versions stored an unsalted SHA-256 hash. Such a user can still log in; after the first successful login
the server replaces the old hash with a PBKDF2 hash and logs this at Information level.

## FxSsh

FxSsh is a lightweight [SSH](http://en.wikipedia.org/wiki/Secure_Shell) server side application as SSH reinforcement of [GitCandy](https://github.com/Aimeast/GitCandy). 

The SSH protocol comes from upstream FxSsh, vendored as a git subtree in `external/FxSsh` (see
[external/README.md](external/README.md)). It gives modern algorithms: host keys ecdsa-sha2-nistp256 and
rsa-sha2-256/512 (no SHA-1 `ssh-rsa` signatures), key exchange mlkem768x25519-sha256, curve25519-sha256,
ecdh-sha2-nistp*, diffie-hellman-group14/16/18-sha2, ciphers aes-gcm and aes-ctr, and hmac-sha2(-etm).
OpenSSH connects with its default settings.

### Features in this repo that was not in the original FxSSH

- Password Authentication is implemented and enabled by default
- Public key authentication with several keys per user (see "User login" below)
- Server keys are autogenerated: the RSA key at first startup, the ECDSA P-256 key at the first startup of a version that supports it. The RSA key of an existing `config.db` is kept, so clients do not see a new host key
- Logging based on Serilog (the FxSsh library log goes to the same Microsoft.Extensions.Logging logger).
- SFTP (version 3): the protocol engine is upstream FxSsh's `SftpService`. `SshServerModule/Sftp/SftpFileSystemAdapter`
  connects it to our `IFileSystem`, so each user stays inside his own root directory (`LocalFileSystem`
  maps the virtual paths and checks that they stay inside the root). SETSTAT applies size, times and
  permissions (rwxrwxrwx; on Windows only the read-only attribute of a file).
- OpenSSH SFTP extensions (announced in SSH_FXP_VERSION): `posix-rename@openssh.com` (rename that replaces
  an existing file atomically; OpenSSH `sftp rename` and SSH.NET `RenameFile(..., isPosix: true)` use it),
  `statvfs@openssh.com` (`df` in OpenSSH sftp, SSH.NET `GetStatus`; the space of the disk of the user root,
  in 4 KiB blocks), `fsync@openssh.com` (`put -f`), `limits@openssh.com` (64 KiB reads and writes, 1 MiB
  packets) and `expand-path@openssh.com` ("~" is the user root "/"; only virtual paths are returned, never
  the physical path). `hardlink@openssh.com` is not offered (OP_UNSUPPORTED).
- Links are not supported: SSH_FXP_SYMLINK and SSH_FXP_READLINK give SSH_FX_OP_UNSUPPORTED. OpenSSH sends
  the two SYMLINK arguments in the opposite order of the draft (target path first, then link path); the
  server does not have to choose an order, because it refuses the request in both cases. If links are
  supported later, the server must read the arguments in the OpenSSH order, like OpenSSH sftp-server.
  Links that exist on the disk and point outside the user root are not listed and cannot be opened.
- Per-path permissions and path filters (issue #59): each user has permissions per virtual directory (list,
  download, upload, overwrite, delete, rename, create directories, chmod, times), for example "upload only" in
  `/incoming`; the most specific path wins. Path filters allow or deny file name patterns (`*.csv`, `*.exe`) and
  hide names completely. Edit them in the user form of the admin UI. Every user starts with `/` = all
  permissions, also users from an older database, so nothing changes until you set rules.
- Running commands (shell and exec) is not implemented. `EnableCommand` is off by default; when it is on, the
  server only echoes the command and closes the channel.
- Server is started using IHostedService interface (useful for standalone service or hosted inside Asp.Net Core)
- Server settings and users are saved in a SQLite database (EF Core). See [Settings storage](#settings-storage).
- Global IP blacklist, optional global IP whitelist, auto-ban after failed logins, and `BindToAddress`. See [Network access settings](#network-access-settings).


### Features planned for the future

The [technical roadmap](docs/ROADMAP.md) lists the planned work, with one GitHub issue for each feature. For
example: encrypted local storage and S3, Azure Blob and Google Cloud Storage backends, groups, quotas,
an audit log, webhooks, a REST API, WebDAV and FTP, and more settings databases.

## Log files

Both hosts log with Serilog. The sinks are in `appsettings.json` under `Serilog:WriteTo` and are **named**
(`File`, `HtmlFile`, and `Console` in ServerConsoleApp), not listed in an array, so that one environment variable
can change one setting of one sink. Relative paths are resolved against the program directory.

| Environment variable | Default | Meaning |
|---|---|---|
| `Serilog__WriteTo__File__Args__path` | `logs/FxSshServer.txt` | Text log file (rolls at 10 MB) |
| `Serilog__WriteTo__HtmlFile__Args__path` | `logs/html/FxSshServer.html` | HTML log file |
| `Serilog__MinimumLevel__Default` | `Information` | Minimum level |

The container image and the systemd unit set the two paths to `/data/logs` and `/var/log/freesftpsharp`. If you add
your own sink in `appsettings.Production.json`, give it a name as a key (`"WriteTo": { "Mine": { "Name": ... } }`);
an array there cannot be combined with the environment variables.

## Network access settings

These fields of the server settings (`ServerSettings`) control who can connect. Network entries are CIDR
(`10.0.0.0/8`, `2001:db8::/32`) or single addresses (`10.1.2.3`, `::1`). IPv4 clients that arrive on the
dual-stack socket as `::ffff:10.1.2.3` match IPv4 entries. Host bits are ignored (`192.168.1.5/24` is
`192.168.1.0/24`). Invalid entries are skipped and logged once. `SshServer.Interfaces.Net.CidrNotation` parses and
validates the entries; the admin UI can use `CidrNotation.IsValid` / `FindInvalid` for input validation.

| Setting | Default | Meaning |
| --- | --- | --- |
| `BindToAddress` | empty | Local addresses to listen on, e.g. `127.0.0.1`, `::1`, `192.168.1.10`. Empty: all addresses, IPv4 and IPv6. `::` also means all addresses (dual stack). Read at start; when no entry is valid, the server does not start |
| `BlacklistedIps` | empty | Networks that may not connect. The connection is closed right after accept, before the SSH identification and key exchange, and logged. Wins over the whitelist |
| `OnlyWhitelistedIps` | `false` | Global whitelist mode: only the networks in `WhitelistedIps` may connect. With an empty list nothing is checked (as for the per-user whitelist), so a half-done setting does not lock everybody out. Loopback is not special here |
| `WhitelistedIps` | empty | The networks for `OnlyWhitelistedIps` |
| `MaxLoginAttemptsBeforeBan` | `5` (new database) | Auto-ban: this many failed password logins from one address within `LoginFailureWindowSeconds` ban the address for `BanDurationSeconds`. `0` turns auto-ban off. A database of an older version keeps its stored value (usually `0`) |
| `LoginFailureWindowSeconds` | `600` | Sliding window for counting failures. `0` turns auto-ban off |
| `BanDurationSeconds` | `1800` | How long a ban lasts. `0` turns auto-ban off |
| `ExemptLoopbackFromBan` | `true` | Never ban `127.0.0.0/8` and `::1` |

The per-user whitelist (`User.OnlyWhitelistedIps` / `User.WhitelistedIps`) is checked in addition, at login.

### User login

- **Public keys.** A user has a list of keys (`User.PublicKeys`): `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521` and
  `ssh-rsa` (signatures rsa-sha2-256/512). A login compares the whole key blob that the client sends, not only the
  fingerprint. A key with an expiry date (`ExpiresAt`, UTC) is refused from that time on. A removed key is refused at
  the next connection. SSH certificates, DSA and security keys (`sk-...`) are not supported. The server checks ed25519
  signatures with BouncyCastle (FxSsh and .NET have no ed25519); it has no ed25519 host key. It registers ssh-ed25519
  as a custom algorithm; the start log has the Info line "Imported custom algorithms: hostkey=[ssh-ed25519]".
- **Allowed methods.** `User.AllowedAuthMethods` (default: all) can limit a user to `PublicKey` or `Password`. A
  refused method fails like a wrong credential (a refused password takes the time of a password check).
- **Multi-step login.** `User.RequireAllOf`, for example `[PublicKey, Password]`, needs every method in this order. The
  server answers the first step with partial success (RFC 4252 section 5.1) and offers only the next method; OpenSSH
  then asks for the password. A step for another user name, or a change of the user's steps, starts again.
- **Upgrade.** The single RSA key of a user of an older version (`RsaPublicKey`, also in an imported `config.db`) is
  moved to the key list at the first start; the user keeps its key and its password.

Auto-ban details:

- Counted are failed **password** logins, also for unknown user names and for users whose IP whitelist does not
  match. Rejected public keys are not counted: clients offer every key they have, so a user with several keys would
  be banned, and keys cannot be guessed like passwords.
- A banned address is dropped at accept like a blacklisted one. A session that is open when the ban starts gets no
  more successful logins.
- A successful login resets no counter (otherwise one valid account would let an attacker try passwords of other
  accounts without limit).
- Bans are kept in memory: a restart lifts them. `IIpBanService` (registered by `AddSshServerSecurity()`) lists the
  active bans and lifts one with `Unban`, for the admin UI.

Settings changes (blacklist, whitelist, ban settings) apply to the next connection; `BindToAddress` and
`ListenToPort` need a restart. `User.LastSuccessfulLogin` is set (UTC) after each successful login.

The old `ServerRootDirectory` setting was never used (each user has `UserRootDirectory`) and has been removed.

## Quotas and bandwidth limits

Each user can have limits (issue #62), set on the Users page; all are off (0) by default:

- **Disk quota**: the size (MiB) and the number of files of the own storage of the user. Each mounted virtual folder
  has its own quota in the mount table; its usage is counted per folder, for every user that mounts it. An upload that
  goes over the quota fails with "Quota exceeded" (SFTP `SSH_FX_FAILURE`) and leaves no partial file.
- **Transfer quota**: the uploaded, downloaded and total MiB until the counters are reset ("Reset transfer counters" on
  the Users page, or the event rule action "Reset transfer quota" on a schedule).
- **Bandwidth**: KiB/s per session for uploads and downloads, with other values for some client networks (for example
  `0` for the LAN).

The usage is counted by the server, so a write never scans the storage. A scan recomputes it: at the first session of a
user that was never scanned, after a change of the quota, with "Rescan quota" (or the event rule action), and every
`Quota:ScanIntervalHours` hours (default `24`, `0` turns the scheduled scan off). The counters are in the settings
database, shared by the nodes. Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#quotas-and-bandwidth).

## Listen port and bind addresses from configuration

The port and the bind addresses are normally stored in the settings database (`ListenToPort`, `BindToAddress`).
`ServerConsoleApp` has no web UI, so both can also be set in the configuration. A configured value **overrides** the
stored setting at runtime. It is never written to the database, and an empty value means "not set".

| Key | Environment variable | Command line | Meaning |
| --- | --- | --- | --- |
| `SshServer:Port` | `SshServer__Port` | `--port 2222` | Listen port, 1-65535. An invalid value stops the server at start with a clear error |
| `SshServer:BindToAddress` | `SshServer__BindToAddress` | `--bind 127.0.0.1,::1` | Addresses to listen on: a comma separated string, or an array (`SshServer:BindToAddress:0`, `SshServer__BindToAddress__0`, a JSON array) |

```sh
ServerConsoleApp --port 2222 --bind 127.0.0.1
SshServer__Port=2222 ServerConsoleApp
```

```json
{ "SshServer": { "Port": 2222, "BindToAddress": [ "127.0.0.1", "::1" ] } }
```

Precedence: command line, environment variables, `appsettings.json`, then the settings database. At start the server
logs the effective port and addresses and whether they come from the configuration or the database. A port below
1024 needs extra rights on Linux (for example `CAP_NET_BIND_SERVICE`); use a higher port with `--port` instead.
`FxSshSftpServer` reads `SshServer:Port` and `SshServer:BindToAddress` from `appsettings.json` and environment
variables (the `--port` and `--bind` shortcuts exist only in `ServerConsoleApp`); its settings page shows when the
port is overridden.

## S3 storage backend

`SshServer.Filesystem.S3` stores the files of a user in an S3 bucket, or below a key prefix in it. It works with AWS S3
and with S3-compatible stores (MinIO, Cloudflare R2, Backblaze B2, Wasabi, DigitalOcean Spaces, ...). Both hosts
register it with `services.AddS3Storage()` under the provider name `s3`. Nothing changes for a server that does not
use it: no S3 client is created and no setting is needed.

Select it for a user, or for a virtual folder, in the admin UI (see [Storage per user and virtual folders](#storage-per-user-and-virtual-folders)).
The secret access key is stored encrypted and is never shown again.

### Options (`S3StorageOptions`)

| Option | Default | Meaning |
| --- | --- | --- |
| `Bucket` | (required) | The bucket. It must exist; the server never creates or removes a bucket. |
| `KeyPrefix` | empty | The prefix that is `/` for the user, for example `users/alice`. Empty: the whole bucket. |
| `Region` | environment | For example `eu-north-1`. Empty: `AWS_REGION` or the profile. With `Endpoint`, the signing region (default `us-east-1`). |
| `Endpoint` | empty | The URL of an S3-compatible store, for example `http://localhost:9000`. Empty for AWS S3. |
| `ForcePathStyle` | `false` | Path-style URLs (`endpoint/bucket/key`). MinIO needs it. |
| `AccessKey`, `SecretKey` | empty | Both or neither. Empty: the credentials of the environment (variables, profile, instance role, IRSA). `SecretKey` is never shown by `ToString()`. |
| `StorageClass` | bucket default | For example `STANDARD_IA`. |
| `ServerSideEncryption`, `KmsKeyId` | bucket default | `AES256`, or `aws:kms` with an optional KMS key id. |
| `UploadPartSize` | 5 MiB | The part size of a multipart upload (5 MiB to 512 MiB), held in memory. The largest file is 10,000 parts (48.8 GiB with 5 MiB). |
| `UploadConcurrency` | 2 | The parts of one upload that are sent while the next part fills (1 to 64). |
| `ReadAheadSize` | 4 MiB | The bytes that one ranged GetObject reads ahead (64 KiB to 512 MiB). |

### Behaviour

- **Directories are virtual.** A directory exists when a key starts with its prefix (`dir/`). `mkdir` writes a
  zero-byte marker object `dir/`, so an empty directory stays. A listing is ListObjectsV2 with the delimiter `/`,
  page by page. Directories have the time of their marker, or 1970-01-01 in a listing.
- **Reads** are ranged GetObject requests through a read-ahead buffer: a sequential download is one request per
  `ReadAheadSize`, not one per 32 KiB SFTP read. The open reads the first block, so a small file stays readable when it
  is renamed or removed while it is open. A file that another writer replaces while it is open gives a failure
  (If-Match on the ETag), never mixed content.
- **Writes** are sequential (no `RandomAccessWrite`). A file smaller than one part is one PutObject; a larger file is a
  streaming multipart upload, and the object appears when the file is closed. A failed part or a failed completion
  aborts the multipart upload. A write at the end of an existing file (a resumed upload, `reput`, or `Append`) copies the
  existing object on the server (UploadPartCopy) or, when it is smaller than one part, reads it into the buffer.
- **Rename** is CopyObject + DeleteObject (a multipart copy above 5 GiB); a directory rename copies every object below
  it, then removes the sources. It is not atomic, and its cost grows with the size.
- **No permissions, no times, no links.** SETSTAT of permissions or times and size changes give `SSH_FX_OP_UNSUPPORTED`;
  an update that changes nothing (the same size, no fields) works. statvfs (`df`) fails: an object store has no size.
- **Errors**: 404 is `NoSuchFile`, 403 is `PermissionDenied`, every other S3 error is `Failure`; the log has the status,
  the S3 error code and the request id, never the bucket or the endpoint.
- **Lost connection**: a session that ends without an SSH_FXP_CLOSE for an open file aborts the upload (AbortMultipartUpload): no object appears and the old object stays. Add a lifecycle rule `AbortIncompleteMultipartUpload` to the bucket for uploads that the server could not abort (a crash of the server).

### IAM permissions

The server needs these actions on the bucket (`arn:aws:s3:::BUCKET`) and its objects (`arn:aws:s3:::BUCKET/PREFIX/*`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::BUCKET",
      "Condition": { "StringLike": { "s3:prefix": ["PREFIX/*"] } } },
    { "Effect": "Allow", "Resource": "arn:aws:s3:::BUCKET/PREFIX/*",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"] }
  ]
}
```

`s3:PutObject` also covers the multipart upload and the copy of a rename. With `aws:kms`, the role also needs
`kms:GenerateDataKey` and `kms:Decrypt` on the key.

### Tests

The conformance suite runs on an in-memory fake S3 client everywhere, and against a real server when
`FREESFTPSHARP_TEST_S3_ENDPOINT` is set (CI: MinIO on the Ubuntu job). Locally:

```sh
docker run -d --rm --name minio -p 19000:9000 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin bitnamilegacy/minio:2025.4.22
FREESFTPSHARP_TEST_S3_ENDPOINT=http://127.0.0.1:19000 dotnet test FreeSftpSharp.sln --filter "Category=S3"
docker stop minio
```
## Google Cloud Storage backend

`SshServer.Filesystem.Gcs` stores the files of a user in a Google Cloud Storage bucket, or below a key prefix in it. Both
hosts register it with `services.AddGcsStorage()` under the provider name `gcs`. Nothing changes for a server that does
not use it: no client is created and no setting is needed.

> **Not selectable yet.** Until the per-user storage configuration (#56) exists, every user has the local disk.
> #56 adds the choice of the provider and these options per user (and the admin UI fields).

### Options (`GcsStorageOptions`)

| Option | Default | Meaning |
| --- | --- | --- |
| `Bucket` | (required) | The bucket. It must exist; the server never creates or removes a bucket. |
| `KeyPrefix` | empty | The prefix that is `/` for the user, for example `users/alice`. Empty: the whole bucket. |
| `CredentialsJson` | empty | The content of a service account key file. A secret, never shown by `ToString()`. |
| `CredentialsFile` | empty | The path of a service account key file. Not together with `CredentialsJson`. |
| `Endpoint` | empty | The URL of an emulator, for example `http://localhost:4443`. Without credentials the requests are not authenticated. Empty for Google Cloud Storage. |
| `StorageClass` | bucket default | `STANDARD`, `NEARLINE`, `COLDLINE` or `ARCHIVE` for new objects. |
| `UploadChunkSize` | 8 MiB | The chunk of a resumable upload, held in memory; a multiple of 256 KiB (256 KiB to 512 MiB). |
| `ReadAheadSize` | 4 MiB | The bytes that one ranged download reads ahead (64 KiB to 512 MiB). |

Without `CredentialsJson` and `CredentialsFile` the server uses the Application Default Credentials
(`GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth application-default login`, or the service account of the VM, GKE pod
or Cloud Run service).

### Behaviour

- **Directories are virtual**, as in the S3 backend: a directory exists when an object name starts with its prefix
  (`dir/`), `mkdir` writes a zero-byte marker object `dir/`, and a listing uses the delimiter `/`.
- **Reads** are ranged downloads of one object generation through a read-ahead buffer; a file that another writer
  replaces while it is open gives a failure, never mixed content.
- **Writes** are sequential. A file smaller than one chunk is one upload request; a larger file is a resumable upload
  whose chunks are sent while the next one fills, and the object appears when the file is closed. A failed chunk, and a
  lost connection (`AbortAsync`), cancel the session without finalizing it, so no object appears and an existing object
  stays as it was. Cloud Storage discards a session that is not used for a week. An exclusive create (`O_EXCL`) is
  checked again at the close (`ifGenerationMatch=0`).
- **A write at the end of an existing file** (a resumed upload, `reput`, `Append`) reads a small object into the
  buffer. For an object of at least one chunk the new data is uploaded as the temporary object `NAME.part-ID` and joined
  by a compose on the server at the close (it is visible in a listing until then, and is removed at an abort).
- **Rename** is copy + delete on the server (rewrite, any size); a directory rename copies every object below it, then
  removes the sources. It is not atomic.
- **No permissions, no times, no links, no size changes** (`SSH_FX_OP_UNSUPPORTED`); statvfs fails.
- **Errors**: 404 is `NoSuchFile`, 401 and 403 are `PermissionDenied`, 412 is `AlreadyExists`, every other error is
  `Failure`; the log has the status and the Google error reason, never the bucket or the endpoint.

### IAM permissions

Grant the service account the role `roles/storage.objectAdmin` on the bucket (or on a managed folder / with an IAM
condition on the object name prefix for one `KeyPrefix`). The server needs `storage.objects.get`, `.list`, `.create` and
`.delete` (a rename and an append use these too; a compose needs `storage.objects.create` and `.get`). It never needs
bucket-level permissions.

### Tests

The conformance suite and the end-to-end tests run against an emulator when `FREESFTPSHARP_TEST_GCS_ENDPOINT` is set
(CI: `fsouza/fake-gcs-server` on the Ubuntu job; the bucket is created by the tests). Locally:

```sh
docker run -d --rm --name fakegcs -p 14443:4443 -e FAKE_GCS_SCHEME=http -e FAKE_GCS_BACKEND=memory \
  -e FAKE_GCS_EXTERNAL_URL=http://127.0.0.1:14443 fsouza/fake-gcs-server:1.56.1
FREESFTPSHARP_TEST_GCS_ENDPOINT=http://127.0.0.1:14443 dotnet test FreeSftpSharp.sln --filter "Category=Gcs"
docker stop fakegcs
```

Verification against a real bucket with a service account is a manual step: set `Bucket` and `CredentialsFile`, run the
same suite by pointing a test at it, and check that the role above is enough.


## Azure Blob storage backend

`SshServer.Filesystem.AzureBlob` stores the files of a user in an Azure Blob Storage container, or below a name prefix
in it. Both hosts register it with `services.AddAzureBlobStorage()` under the provider name `azure-blob`. Nothing
changes for a server that does not use it: no client is created and no setting is needed.

> **Not selectable yet.** Until the per-user storage configuration (#56) exists, every user has the local disk.
> #56 adds the choice of the provider and these options per user (and the admin UI fields).

### Options (`AzureBlobStorageOptions`)

Set exactly one of `ConnectionString`, `SasUrl` and `AccountName`. The provider checks the options itself.

| Option | Default | Meaning |
| --- | --- | --- |
| `Container` | (required) | The container. It must exist; the server never creates or removes a container. Empty only with a `SasUrl` of the container. |
| `KeyPrefix` | empty | The blob name prefix that is `/` for the user, for example `users/alice`. Empty: the whole container. |
| `ConnectionString` | empty | A connection string of the account (also Azurite). A secret, never shown by `ToString()`. |
| `SasUrl` | empty | A SAS URL of the container (or of the account, with `Container`). A secret, never shown by `ToString()`. |
| `AccountName` | empty | The account; the server signs in with `DefaultAzureCredential` (managed identity, environment variables, Azure CLI). |
| `Endpoint` | `https://ACCOUNT.blob.core.windows.net` | The blob service address for `AccountName`, for a sovereign cloud or Azurite. |
| `AccessTier` | account default | `Hot`, `Cool` or `Cold` for new blobs. |
| `UploadBlockSize` | 4 MiB | The size of one block of an upload (64 KiB to 256 MiB), held in memory. The largest file is 50,000 blocks (195 GiB with 4 MiB). |
| `UploadConcurrency` | 2 | The blocks of one upload that are sent while the next block fills (1 to 64). |
| `ReadAheadSize` | 4 MiB | The bytes that one ranged download reads ahead (64 KiB to 512 MiB). |

### Behaviour

- **Directories are virtual.** A directory exists when a blob name starts with its prefix (`dir/`). `mkdir` writes a
  zero-length marker blob `dir` with the metadata `hdi_isfolder=true` (the convention of Storage Explorer and Data
  Lake), so an empty directory stays. A listing is the hierarchy listing with the delimiter `/`, page by page.
  Directories have the time of their marker, or 1970-01-01 in a listing without one. A file name cannot end with a dot
  (Azure removes it), and a name has at most 1,024 characters and 254 segments.
- **Reads** are ranged downloads through a read-ahead buffer: a sequential download is one request per `ReadAheadSize`.
  A file that another writer replaces while it is open gives a failure (If-Match on the ETag), never mixed content.
- **Writes** are sequential (no `RandomAccessWrite`). A file smaller than one block is one Put Blob; a larger file is a
  block blob (Put Block per block, Put Block List when the file is closed), so the blob appears when the file is
  closed. A write at the end of an existing file (a resumed upload, `reput`, or `Append`) keeps the blocks that the
  server wrote and adds new ones; a blob that another tool wrote is read through the server into new blocks.
- **Rename** is Copy Blob (inside one account, done by the service) and Delete Blob; a directory rename copies every
  blob below it, then removes the sources. It is not atomic, and its cost grows with the size. The capabilities are
  `Append`, `Rename` and `ServerSideCopy`.
- **No permissions, no times, no links.** SETSTAT of permissions or times and size changes give `SSH_FX_OP_UNSUPPORTED`
  (the last modified time of a blob cannot be set); an update that changes nothing works. statvfs (`df`) fails.
- **Errors**: 404 is `NoSuchFile` (a missing container is a failure), 403 is `PermissionDenied`, 409 `BlobAlreadyExists`
  is `AlreadyExists`, every other error is `Failure`; the log has the status, the Azure error code and the request id,
  never the account or the container.
- **Lost connection**: a session that ends without an SSH_FXP_CLOSE for an open file drops the upload: the block list
  is never committed, so no blob appears and the old blob stays. The staged blocks are invisible, and Azure removes
  them after seven days.

### Permissions

With `AccountName` the identity needs the role **Storage Blob Data Contributor** on the container (or the account).
Reading needs only Storage Blob Data Reader. A SAS URL needs the permissions read, add, create, write, delete and
list (`racwdl`). `DefaultAzureCredential` is checked by hand against a real account, as there is no emulator for it:
run the server with a managed identity (or `az login`), set `AccountName` and `Container`, and upload, download, list,
rename and delete through `sftp`.

### Tests

The conformance suite and the end-to-end tests run against Azurite when `FREESFTPSHARP_TEST_AZURITE` is set to the
address of its blob service (CI: Azurite on the Ubuntu job); without it they are skipped. The Azure SDK is newer than
Azurite, so start Azurite with `--skipApiVersionCheck`. Locally:

```sh
docker run -d --rm --name azurite -p 10000:10000 mcr.microsoft.com/azure-storage/azurite:3.37.0 azurite-blob --blobHost 0.0.0.0 --skipApiVersionCheck --loose
FREESFTPSHARP_TEST_AZURITE=http://127.0.0.1:10000 dotnet test FreeSftpSharp.sln --filter "Category=Azure"
docker stop azurite
```

## Encrypted storage

The user roots can be stored encrypted at rest (AES-256-GCM, a key per file, key rotation). It is off by default.
Configure a key; see [docs/ENCRYPTED-STORAGE.md](docs/ENCRYPTED-STORAGE.md) for the configuration, the limits and the
file format. Then select "Local disk (encrypted)" for a user or a virtual folder, or set `Storage:Encryption:Enabled`
to `true` to encrypt the root directory of every user without a storage configuration.

## Storage per user and virtual folders

By default a user has the local disk at its root directory, as before. On the Users page an admin can select another
storage for a user instead: every registered provider (`local`, `local-encrypted`, `s3`) with its own fields, and a
"Test connection" button that lists the root with the unsaved settings. The fields come from the options record of the
provider, so a new backend needs no UI code.

A **virtual folder** (page "Virtual folders") is a named storage location that is mounted into the file system of one
or more users at a path, for example a shared S3 prefix at `/incoming` or an encrypted `/archive`. The user sees it as
a directory; the permissions and path filters of the user apply to its virtual path (`/incoming = Upload`).

- A mount point and the directories that hold one cannot be removed or renamed.
- A rename from one storage into another (for example `rename /a /incoming/a`) answers `SSH_FX_OP_UNSUPPORTED`;
  copy the file instead.
- Removing a virtual folder unmounts it from every user; the files in its storage stay.

Secrets of a storage configuration (for example the S3 secret key) are encrypted in the settings database with the
ASP.NET Core data protection keys of `DataProtection:KeysPath` (see below). They are never shown in the UI after they
are saved and never written to the log or the audit events. Keep the keys directory: without it the stored secrets
cannot be read and must be entered again. Two hosts that share one settings database must share the keys directory too.

## Settings storage

The server settings (port, banner, host key, ...) and the users are stored with EF Core in a SQLite database.
The code is in `SshServer.Settings.Sql` (`SqlSettingsRepository`, `SettingsDbContext`). The schema is created and
upgraded with EF Core migrations (`SshServer.Settings.Sql/Migrations/Sqlite`) when the server starts.

Configuration (`appsettings.json`, environment variables such as `Settings__Provider`, or the command line):

| Key | Default | Meaning |
| --- | --- | --- |
| `Settings:Provider` | `Sqlite` | `Sqlite`, or `LiteDb` for the old LiteDB file (obsolete) |
| `ConnectionStrings:Settings` | `Data Source=freesftpsharp.db` | The SQLite connection string. A relative path is relative to the application directory (`AppContext.BaseDirectory`), not to the current directory |
| `Settings:LiteDbPath` | `config.db` in the current directory, else in the application directory | The LiteDB file: imported once by `Sqlite`, used directly by `LiteDb` |

```json
{
  "Settings": { "Provider": "Sqlite" },
  "ConnectionStrings": { "Settings": "Data Source=/var/lib/freesftpsharp/freesftpsharp.db" }
}
```

### Audit log

Every file operation, login, ban and change of a user or of the server settings is an event on the internal event
bus. The audit log writes each event to the table `AuditEntries` of the same SQLite database (nothing to configure)
and shows it on the Audit page. Entries older than `Audit:RetentionDays` (default `90`; `0` keeps all) are removed
once a day. Logins, failed logins and bans are also written to the server log as one line each, for log readers such
as fail2ban, for example:

```
Auth LoginFailed user bob from 203.0.113.9 method password protocol SSH: wrong password
```

With `Settings:Provider=LiteDb` there is no audit table and the Audit page says so.

### Webhooks

A webhook sends events as signed JSON over HTTPS to another system: start a workflow when a file arrives, send
logins to a SIEM, or let a scanner refuse an upload. Add them on the Webhooks page; nothing is sent until you do.
An asynchronous webhook gets each event through an outbox in the settings database, with retries (10 s, 1 min, 5 min,
30 min, 2 h) and survives a restart; a slow receiver never delays a transfer. A synchronous webhook answers before a
`PreUpload`, `PreDownload` or `PreDelete` runs: `2xx` allows it, `403` refuses it (the client gets "permission denied"
with the `message` of the answer), and an error or a timeout refuses it unless the webhook is set to fail open.
The payload, the signature check for a receiver and the options (`Webhooks:AllowInsecureWebhooks`,
`Webhooks:DeliveryRetentionDays`, `Webhooks:MaxConcurrentDeliveries`) are in [docs/WEBHOOKS.md](docs/WEBHOOKS.md).

### Event rules

An event rule automates the server without code: "on an upload to `/incoming/*`, move the file to
`/processed/{{Name}}` and send an email", or "every night at 03:00 remove the files older than 30 days in `/tmp`".
Add rules on the Event rules page; nothing runs until you do. The actions are move, copy, delete, create directories,
check that files exist, compress to zip, data retention, email (SMTP in `EventRules:Smtp`), a webhook of the Webhooks
page, and a command, which is off unless the operator sets `EventRules:AllowCommands=true` and lists the executables
in `EventRules:AllowedCommands`. A rule on a `Pre*` event runs before the operation and refuses it when an action fails.
Triggers, conditions, placeholders and options are in [docs/EVENT-RULES.md](docs/EVENT-RULES.md).

### Upgrade from LiteDB (config.db)

Earlier versions stored everything in a LiteDB file `config.db` in the current directory. When the SQLite
database is new and a `config.db` exists, the server imports the settings (including the host key, so clients
do not see a changed host key) and all users from it once, and logs a warning. `config.db` is opened read-only
and is not changed or deleted; after the import it is no longer used, so you can archive it.

The LiteDB storage (`SshServer.Settings.LiteDb`) is **obsolete**. It is kept for the import and can still be
selected with `Settings:Provider` = `LiteDb`, but it will be removed in a later version.

### Another database

The model is provider-neutral (lists are JSON text columns). To add an EF Core provider such as SQL Server, add a
value to `SettingsProvider`, its `Use...` call in `Startup.CreateDbContextOptions`, and its own migrations.
To change the model, add a SQLite migration:

```sh
dotnet ef migrations add <Name> --project SshServer.Settings.Sql --output-dir Migrations/Sqlite
```

## Sample

### Server

`ServerConsoleApp/Program.cs` is the smallest host: it reads the configuration, registers the settings
database, the local disk storage and the SSH server, and runs the generic host. `FxSshSftpServer` hosts the
same server in ASP.NET Core together with the admin UI.

### Client (SSH.NET)

```csharp
using Renci.SshNet;

using var client = new SftpClient("localhost", 2222, "alice", "a-password");
client.Connect();
foreach (var entry in client.ListDirectory("/"))
    Console.WriteLine(entry.FullName);
client.Disconnect();
```

### License

The MIT license
