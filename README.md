
# SftpServer (SSHServer)

Sftp Server implementation based on SSHServer library based heavily on [FxSsh](https://github.com/Aimeast/FxSsh). This fork (based on https://github.com/0xFireball/SSHServer) implements the sftp subsystem and a Graphical user interface for administration of users and server settings.

## Current status
All basic Sftp command are now implemented except handling symbolic links. However some implementations such as returning correct file attributes are not finalized. Server was tested with FileZilla client only. There are probably some bugs left to fix. 
You are welcome to create PR's. The planned work is described in the [technical roadmap](docs/ROADMAP.md).

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
| `ServerConsoleApp user add <name> --root <dir> [--password-stdin \| --public-key <file>]` | Adds a user. `--public-key` takes an OpenSSH `ssh-rsa` line (an `id_rsa.pub` file) or a PEM public key; only RSA keys are supported. Without either option on a terminal, it asks for the password twice. |
| `ServerConsoleApp user list` | Lists the users: name, login kind (`password`, `key`) and root directory. It never shows hashes or keys. |
| `ServerConsoleApp user remove <name>` | Removes a user. The files in the root directory are not deleted. |

Exit codes: 0 = done, 1 = the operation failed (the reason is on stderr), 2 = wrong arguments (the usage is on stderr).

## Admin web UI (FxSshSftpServer)

`FxSshSftpServer` hosts the SSH/SFTP server and a Blazor admin UI for the server settings and the SFTP users.
The UI has one local admin account. It is separate from the SFTP users.

The UI is a Blazor Web App (interactive server rendering) with Bootstrap 5.3 and Bootstrap Icons. All CSS, fonts and
scripts are local files in `wwwroot/lib`, so the UI needs no internet access. It has these pages:

| Page | What it shows and changes |
| --- | --- |
| Dashboard (`/`) | The effective listen port and bind addresses (and whether they come from the configuration or the database), the number of users, the active bans, the host key fingerprints |
| Users (`/users`) | A searchable user list; add, edit and delete (with a confirmation) users: root directory (with a warning when it does not exist), password (salted PBKDF2), a generated RSA key pair (the browser downloads the private key once; the fingerprint is shown), the per-user IP whitelist (CIDR, validated), the last successful login |
| Server settings (`/general`) | Listen port and bind addresses (with a note when `SshServer:Port` / `SshServer:BindToAddress` override them), server banner, idle timeout, `EnableCommand`, `EnableDirectTcpIp` (with a security warning), the host key fingerprints (never the private keys) and the algorithms the server offers |
| IP access and bans (`/access`) | The global blacklist, the global whitelist mode and list (CIDR, validated), the auto-ban settings, and the active bans with an "Unban" action |

The UI has a dark mode (the half-circle button in the top bar; it follows the OS by default) and works on phone widths.

### Set the admin password

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

If no valid admin credential is configured, the UI is closed: every request gets `503 Service Unavailable` with a
short help text, and the log has an error that tells what is missing. The SSH server still runs.

All pages and the Blazor hub (`/_blazor`) need a login (cookie authentication, fallback authorization policy).

The login cookie and the antiforgery tokens are protected with ASP.NET Core data protection keys. The keys are
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
- Public Key authentication relying on key fingerprint
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
  supported later (#25), the server must read the arguments in the OpenSSH order, like OpenSSH sftp-server.
- Running commands remotely is disabled by default (code is commented out but will later be a setting per user)
- Server is started using IHostedService interface (useful for standalone service or hosted inside Asp.Net Core)
- Server settings and users are saved in a SQLite database (EF Core). See [Settings storage](#settings-storage).
- Global IP blacklist, optional global IP whitelist, auto-ban after failed logins, and `BindToAddress`. See [Network access settings](#network-access-settings).


### Features planned for the future
- Storage of a user on S3 or another backend, selected per user (#56). The S3 backend exists (see [S3 storage backend](#s3-storage-backend)); Azure Blob Storage and Google Cloud Storage follow (#54, #55).
- More settings databases through EF Core (e.g. SQL Server / Azure SQL), selected by configuration
- SCP subsystem

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

> **Not selectable yet.** Until the per-user storage configuration (#56) exists, every user has the local disk.
> #56 adds the choice of the provider and these options per user (and the admin UI fields).

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
- **Known limit**: a lost connection during an upload completes the object with the data received so far (like a
  partial file on a local disk). An abort on disconnect needs an abort path in the storage interface (follow-up of #53).
  Add a lifecycle rule `AbortIncompleteMultipartUpload` to the bucket for uploads that the server could not abort.

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

### Server (Powered by this library)

```csharp
using FxSsh;
using FxSsh.Services;
using System;
using System.Text;
using System.Threading.Tasks;

namespace SshServerLoader
{
    class Program
    {
         static async Task Main(string[] args)
        {
             await new HostBuilder()
            .ConfigureServices((hostContext, services) =>
            {
                services.AddLogging();
                Log.Information("Starting host service");
                services.AddHostedService<HostedSftpServer>();
            })
            .RunConsoleAsync();
        }
    }
}
```

### Client (powered by SSH.NET client)

```csharp
using Renci.SshNet;
using System;
using System.Net;

namespace TestClient
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var testUsername = "test_person";
            var testPassword = "1234";


            var connInfo = new ConnectionInfo(IPAddress.Loopback.ToString(), 22, testUsername,
                new AuthenticationMethod[]
                {
                    // Password auth
                    new PasswordAuthenticationMethod(testUsername, testPassword)
                }
            );

            using var sftpclient = new SftpClient(connInfo);
            sftpclient.Connect();
            sftpclient.ListDirectory("/");
            sftpclient.Disconnect();
            
            Console.ReadLine();
        }
    }
}
```

### License

The MIT license
