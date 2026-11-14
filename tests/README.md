# FreeSftpSharp tests

One xUnit v3 project: `tests/FreeSftpSharp.Tests`. It is part of `FreeSftpSharp.sln`.

## Run

```sh
dotnet test FreeSftpSharp.sln
```

Run one class or one test:

```sh
dotnet test FreeSftpSharp.sln --filter "FullyQualifiedName~SshNetFileOperationTests"
dotnet test FreeSftpSharp.sln --filter "FullyQualifiedName~Wrong_password_is_rejected"
```

Show each test and its time: add `--logger "console;verbosity=normal"`.

The suite takes about 10 seconds. It needs no network, no admin rights and no `config.db`. Each test class
gets its own server on a free port and its own temporary directory, so the classes run in parallel.

The project uses `xunit.v3.mtp-off` with `xunit.runner.visualstudio` (VSTest). That is why a plain
`dotnet test FreeSftpSharp.sln` works with the .NET 11 SDK without a `global.json`.

## What is covered

| Folder / class | Kind | What it tests |
| --- | --- | --- |
| `Storage/FileSystemConformanceTests<TFixture>` | conformance (abstract) | the contract of `IFileSystem` and `IFileHandle`, one test per operation and per failure case: stat (root, file, directory, missing, below a file), list (no `.`/`..`, missing, a file), open/read/write (EOF, write past EOF, overwrite, large sequential write, create/truncate/exclusive, missing file or parent, a directory, append, access of the handle, initial permissions), flush, handle stat and set attributes, mkdir, delete file/directory (missing, not empty, wrong type, root), rename (missing, existing target, replace, file onto a directory, root), set size/times/permissions, storage space, path traversal and `\`, case of paths as the `CaseInsensitivePaths` capability declares it, cancellation. A test that needs a capability checks `Capabilities`: with it the operation works, without it the operation throws `OpNotSupported` |
| `Storage/InMemoryFileSystemConformanceTests`, `InMemoryObjectStoreConformanceTests`, `LocalFileSystemConformanceTests` | conformance | the whole suite for `InMemoryFileSystem` with all capabilities, without any capability (like an object store) and for `LocalFileSystem` on a temporary directory |
| `Storage/PermissionFileSystemTests` | unit (`InMemoryFileSystem`) | the permission decorator: upload-only can create but not list, download, overwrite, delete, rename or mkdir; a more specific directory overrides its parent; overwrite without upload; an upload-only open is exclusive so a file that appears meanwhile is not replaced; download-only; chmod/times/size need their permission, also through a handle; rename needs the permission in both directories, overwrite to replace, and is refused for a directory with own rules; stat needs some permission; normalized paths; another spelling on a case-insensitive storage; denied, allowed and hidden patterns; backend errors pass through |
| `Storage/PermissionFileSystemConformanceTests`, `PermissionFileSystemDenyEverythingTests` | conformance, unit | the whole suite through the decorator with rules that allow everything; with `/ = None` every operation of `IFileSystem` (checked by reflection) fails with `PermissionDenied` and nothing reaches the backend (`RecordingFileSystem`) |
| `Storage/StorageProviderTests` | unit | `AddSshServerStorage` + `AddLocalDiskStorage` give a user the local disk at the user root, one registration per provider, lookup by name without case, unknown and duplicate names, typed options and their validation |
| `Storage/Encrypted/EncryptedFileFormatTests` | unit (known-answer vectors, temp dir) | the file format v1 of the encrypted storage: key id, HKDF file key, the exact bytes of an empty and a 5 byte file, SHA-256 of a 64 KiB and a 140000 byte file (made with an independent implementation), the known bytes read back, file size and plaintext size both ways, lengths of cut files |
| `Storage/Encrypted/EncryptedFileSystemTests` | unit (temp dir) | the disk has the header and no plaintext, the same content gives other bytes, plaintext sizes in stat and list, reads at any offset (chunk edges, random), a writing handle reads its data; a flipped byte (header, chunks, tags), swapped chunks, a chunk of another file, a cut file (also at a chunk boundary and without the empty last chunk), appended bytes and a plaintext file give `Failure`; the message has no key; key rotation, an unknown key, a wrong key with the same id; capabilities, writes to an existing file, fsync |
| `Storage/Encrypted/EncryptedFileSystemConformanceTests` | conformance | the whole suite for the encrypted storage on `LocalFileSystem`, without `RandomAccessWrite` and `Append` |
| `Storage/Encrypted/EncryptedStorageConfigurationTests` | unit (generic host) | `AddEncryptedLocalStorage` and `Storage:Encryption`: off without configuration, the start fails with a clear message (no key in it) for a missing active key, a wrong length, bad base64, duplicate ids, a missing key file or one that others can read; enabled gives every user the encrypted disk with the active key; options never print a key; provider options |
| `Unit/LocalFileSystemTests` | unit | `VirtualPath.Normalize` and `GetPhysicalPath` with traversal inputs (`/../../etc/passwd`, `..\..\config.db`, `/a/b/../../../../c`, `//double//slash`, `/.../x`, empty, `.`), a sibling directory with the same prefix as the root, the root cannot be removed or moved, a listing has no `.`/`..` |
| `Unit/LocalFileSystemLinkTests` | unit (temp dir, symbolic links) | a link or junction inside the root to a directory or file outside it is refused (`FileSystemException` with `PermissionDenied`) for every operation, also relative links, links in subdirectories, chains of links and a dangling link to a new file outside; the root reached through a link to its parent cannot be removed, moved or changed; links that stay inside the root, a link to the root, and a root that is itself a link keep working; a link loop gives an error |
| `Sftp/SftpFramingTests` | unit (SFTP packets) | framing of the upstream `SftpService`: one packet split over several calls, several packets in one call, a partial packet at the end, invalid lengths; one response for each request, in order |
| `Sftp/SftpRealPathTests` | unit (SFTP packets) | `SftpFileSystemAdapter.NormalizePath` and SSH_FXP_REALPATH: the canonical path, `..` stays at the root, `~` is the root |
| `Sftp/SftpFileOperationTests` | unit (SFTP packets, temp dir) | every request through `SftpService` + `SftpFileSystemAdapter` + `LocalFileSystem`: status codes of the failure cases (REMOVE of a missing file gives NO_SUCH_FILE, REMOVE of a directory, RMDIR of a file/root/non-empty directory, MKDIR of an existing path or without parent, RENAME to an existing file, open flags), READ limit, FSTAT, SETSTAT/FSETSTAT size, times and permissions, READDIR with `.`/`..` in batches, unsupported requests, `OnClose` closes the handles |
| `Sftp/SftpPathTraversalTests` | unit (SFTP packets, temp dir) | no request reaches the secret file next to the root; writes, renames and mkdir to `..` paths land in the root; status messages never contain the physical path; PermissionDenied of the storage gives PERMISSION_DENIED |
| `Sftp/SftpExtensionTests` | unit (SFTP packets, temp dir) | the OpenSSH extensions in VERSION (no hardlink; a file system without the optional interfaces announces only limits and expand-path); posix-rename replaces a file, moves a file and a directory, missing source, file onto a directory, directory onto an existing path, the root cannot be moved or replaced, sources outside the root are not found, targets outside the root land inside, read-only server; fsync of a file, an unknown/directory/closed handle; limits values and a 64 KiB write+read; expand-path ("~" is "/", "~user" is refused, no physical path); statvfs of the root (blocks match the disk), of a file, of a missing path, ST_RDONLY on a read-only server; hardlink, SYMLINK in both argument orders and other extensions give OP_UNSUPPORTED |
| `Sftp/SftpSymbolicLinkTests` | unit (SFTP packets, temp dir, symbolic links) | every request through a link to outside the root gives PERMISSION_DENIED and changes nothing outside, the listing hides such a link, the status message has no physical path, a link inside the root works |
| `Sftp/SftpFailureLoggingTests` | unit (captures the static FxSsh log, runs alone) | failed SFTP requests are logged at Debug (missing path, denied access, an operation that the storage does not support) or Info (FAILURE of a file operation), an unexpected exception at Fail with the exception |
| `Sftp/SftpInMemoryStorageTests` | unit (SFTP packets, `InMemoryFileSystem`) | the engine and the adapter on the in-memory backend; every `FileSystemError` gives its SSH_FX code without the backend message; IsADirectory of OPEN and REMOVE gives PERMISSION_DENIED; a backend without capabilities takes a sequential upload and answers OP_UNSUPPORTED for random writes, rename, times, size and append; statvfs of a storage without a size fails |
| `Sftp/SftpFileAttributesTests` | unit | the ATTRS wire format of the upstream `SftpFileAttributes`, also with only uid, only gid, only atime or only mtime |
| `Settings/SqlSettingsRepositoryTests` | unit (in-memory SQLite) | default settings of a new database, update of settings, add/get/update/remove of users with all fields (also permissions and path filters), unknown users, case-insensitive duplicate usernames, persistence in a file, a database of the previous schema is migrated (new columns get their defaults, the stored values stay; users of a database before #59 get `/` = All) |
| `Settings/LiteDbImportTests` | unit (temp files) | a `config.db` made with the LiteDB repository is imported into a new SQLite database (settings, host key, users), the file is not changed, no second import, no `config.db` gives new defaults, the LiteDB repository stores permissions and path filters and the import copies them |
| `Settings/SettingsConfigurationTests` | unit | `Settings:Provider`, `ConnectionStrings:Settings` and `Settings:LiteDbPath`: defaults, paths relative to the app directory, LiteDb selection, unknown provider, `AddSshServerSettings` registrations |
| `Settings/ListenConfigurationTests` | unit | `SshServer:Port` / `SshServer:BindToAddress`: options binding (array, comma separated, `--port`/`--bind` switch mappings), precedence configuration over the stored settings (stored settings unchanged), port validation 1-65535 |
| `EndToEnd/ConfiguredPortTests` | end-to-end (SSH.NET) | the stored port is 1, the configured port is a free one: SSH.NET connects on the configured port, nothing listens on the stored port, the stored setting is not changed |
| `Unit/HostKeysTests` | unit | the stored RSA host key (base64 CSP blob or PEM) converts to PEM with the same key, a public-only blob is rejected, host key algorithms are ecdsa-sha2-nistp256, rsa-sha2-512, rsa-sha2-256 (no ssh-rsa), an ECDSA key is made once and saved |
| `Unit/UserAdministrationServiceTests` | unit (temp dir) | the shared user service (admin UI and CLI): PBKDF2 hash, missing root is created, name rules, minimum password length, duplicate names in any letter case, remove keeps the files, OpenSSH and PEM public keys become the stored CSP blob, bad keys (ed25519, garbage) are rejected |
| `Unit/UserCommandTests` | unit | `ServerConsoleApp user add/list/remove`: password from stdin (CRLF), no-echo prompt on a terminal (mismatch fails), `--public-key` file, wrong usage gives exit code 2, bad input and duplicates give exit code 1, list never shows secrets, remove |
| `EndToEnd/UserCommandEndToEndTests` | end-to-end (built `ServerConsoleApp` process, SSH.NET) | `user add` in an empty directory (password on stdin, root created, default database, no server start, no logs), `user list`, duplicate rejected, then the server starts and SSH.NET logs in and uploads; `user remove` stops the login |
| `Unit/PathRuleResolverTests` | unit | `EffectivePermissionsService` and `PathRuleResolver`: "/" defaults to All, the longest matching directory wins (not a name prefix), keys are normalized, a case-insensitive storage matches other spellings (case, trailing dots and spaces), filter patterns ignore case, deny wins over allow, hidden names hide everything below, the validator of the admin UI |
| `Unit/UserLogicsTests` | unit | public key check by SHA-256 fingerprint, IP whitelist (also for IPv4-mapped IPv6 addresses) |
| `Unit/SessionTimeoutsTests` | unit | `IdleTimeout` gives an inactivity timeout, or keepalive probes when it is 0 |
| `Connections/ConnectionRegistryTests` | unit (`FakeTimeProvider`) | `ConnectionRegistry`: register (new id, address, time, no user), oldest first, login, client version, activity, snapshots do not change, a transfer with the growing byte count ends on dispose, unregister once with the Disconnected event, `DisconnectAsync` calls the close callback with the reason and removes the entry, unknown ids are ignored, a failing event handler is logged |
| `Connections/ConnectionTrackingFileSystemTests` | unit (`InMemoryFileSystem`) | the decorator: writes are an upload and reads a download with the bytes so far, the transfer ends when the file is closed, every operation records activity, storage errors are unchanged |
| `EndToEnd/SshNetConnectionRegistryTests` | end-to-end (SSH.NET) | two clients as different users are in the registry with their user, address, protocol, auth method and client version, and leave it within one second of their disconnect; `DisconnectAsync` closes the client (the request in flight fails with `SshException`) and removes the entry; an upload shows the growing byte count and ends when the file is closed |
| `WebUi/ConnectionsPageTests` | bUnit | the Connections page: empty note, user/address/transfer bytes, auto refresh with the fake clock, disconnect only after confirmation |
| `EndToEnd/SshNetAuthenticationTests` | end-to-end (SSH.NET) | connect, wrong password is rejected, `Disconnect` does not wait for a timeout |
| `EndToEnd/SshNetPasswordMigrationTests` | end-to-end (SSH.NET) | login of a user with an old SHA-256 hash, the stored hash is PBKDF2 afterwards and the next login works; wrong password; PBKDF2 user; unknown user |
| `EndToEnd/PublicKeyAndWhitelistTests` | end-to-end (SSH.NET) | public key login, another key and a user without a key are rejected, unknown user, IP whitelist allows and rejects |
| `EndToEnd/AlgorithmNegotiationTests` | end-to-end (raw KEXINIT, SSH.NET) | the server's KEXINIT has no weak algorithms (ssh-rsa, *-sha1 kex, CBC, hmac-md5/sha1) and has curve25519, AES-GCM/CTR, hmac-sha2(-etm); SSH.NET connects with each host key algorithm and fails with only ssh-rsa or group1-sha1 |
| `EndToEnd/IdleTimeoutTests` | end-to-end | with `IdleTimeout` = 1 s, a client that sends nothing and an idle SFTP session are disconnected |
| `EndToEnd/SshNetFileOperationTests` | end-to-end (SSH.NET) | mkdir, 3 MB upload/download with byte compare, list, stat of file and directory, missing paths, overwrite with a smaller file, empty file, append, rename, delete, rmdir, the session survives a failed open |
| `EndToEnd/SshNetEncryptedStorageTests` | end-to-end (SSH.NET, encrypted user root) | a 3 MB upload is ciphertext on disk and downloads byte for byte, stat and list give the plaintext size, reads at offsets, a changed byte on disk gives an error, a random write gives OP_UNSUPPORTED |
| `EndToEnd/SshNetPathTraversalTests` | end-to-end (SSH.NET) | `/../config.db` cannot be read, an upload to `/../x` lands in the user root, `ListDirectory("/..")` lists the root |
| `EndToEnd/SshNetExtensionTests` | end-to-end (SSH.NET) | `RenameFile(..., isPosix: true)` replaces an existing file (posix-rename), plain `RenameFile` still does not overwrite, posix-rename from outside the root fails, `GetStatus` (statvfs) gives the disk size, `GetStatus` of a missing path fails |
| `EndToEnd/SshNetSymbolicLinkTests` | end-to-end (SSH.NET, symbolic links) | a link in the user root to the directory with `config.db` gives permission denied for download, list, stat, upload, mkdir, delete and rename, the listing does not show it, and the client cannot create a link (SSH_FXP_SYMLINK is not supported) |
| `EndToEnd/SftpSessionTeardownTests` | end-to-end (SSH.NET, Linux) | a lost connection (no CHANNEL_CLOSE) closes the files that the SFTP session has open |
| `EndToEnd/OpenSshPermissionTests` | end-to-end (OpenSSH `sftp`) | with `/incoming = Upload` and `/incoming/sub = All`: `put` of a new file works; `ls`, `get`, overwrite, `rm`, `rename`, `mkdir` in `/incoming` give "Permission denied"; everything works in `/incoming/sub`; a denied `*.exe` cannot be uploaded or renamed to; a hidden `*.secret` is not listed and is "not found" |
| `EndToEnd/OpenSshSftpTests` | end-to-end (OpenSSH `sftp`) | put/get of 2 MB, 200 B and 0 B files, get of 8 MB with 256 requests in flight over a slow connection (the responses stay whole and in order when the channel window is full), ls, rename, rm, rmdir, `cd ../..` + `pwd`, overwrite 2 MB with 200 B, `get ../../config.db` fails, `rename` over an existing file replaces it (posix-rename) and `rename -l` does not, `df` shows the disk size (statvfs), `put -f` sends fsync, sftp uses the 64 KiB buffers of limits@openssh.com, sftp exits by itself, connect with the OpenSSH default algorithms (no `+ssh-rsa`), a known_hosts entry with the old `ssh-rsa` key still matches, only-weak-algorithm clients cannot connect |
| `Unit/PasswordHasherTests`, `Unit/AdminCredentialValidatorTests` | unit | the shared PBKDF2 password hash (`SshServer.Interfaces.Security.PasswordHasher`): round trip, wrong password, tampered salt/key/iterations, malformed and plaintext values; admin user name check |
| `Unit/UserPasswordVerificationTests` | unit | SFTP user passwords (`UserLogics.VerifyUserPassword`): PBKDF2 and old SHA-256 hashes, correct and wrong passwords, tampered hashes, the old hash is upgraded to PBKDF2 once and the upgrade is logged without the password |
| `Unit/CidrNotationTests` | unit | the shared CIDR helper: IPv4/IPv6 networks and single addresses, host bits, IPv4-mapped IPv6, invalid input (prefix out of range, host names, scope ids, short IPv4 forms), matching |
| `Unit/LoginBanTrackerTests` | unit | auto-ban after N failures in a sliding window, the ban expires, loopback exemption, IPv4-mapped addresses, 0 = off, `Unban`, clean-up of old records, defaults (`FakeTimeProvider`) |
| `Unit/IpFilterTests` | unit | global blacklist, global whitelist mode (empty list = no check), blacklist wins, banned addresses |
| `Unit/SecurityRegistrationTests` | unit | `AddSshServerSecurity`: `HostedServer` and `IIpBanService` share one `LoginBanTracker`; `AddSshServerConnections`: `HostedServer` and the admin UI share one `IConnectionRegistry` |
| `EndToEnd/IpFilterAndBanTests` | end-to-end (SSH.NET, raw TCP) | a blacklisted / not whitelisted client gets no identification line; ban after 3 wrong passwords or unknown users (loopback exemption off), the ban expires (fake clock), `Unban`; `LastSuccessfulLogin` is set only on success |
| `EndToEnd/BindToAddressTests` | end-to-end (raw TCP) | `BindToAddress` = 127.0.0.1 answers on 127.0.0.1 and refuses ::1; without it both answer (the IPv6 checks are skipped when the machine has no ::1) |
| `Unit/LoginThrottleTests` | unit | lockout after N failed logins, the lockout ends, success clears the failures (`FakeTimeProvider`) |
| `Unit/AdminPasswordCommandTests` | unit | `--hash-admin-password` prints a hash that verifies, rejects short passwords |
| `Logging/LoggingConfigurationTests` | unit + in-memory web host | the Serilog section of both `appsettings.json` files loads (default Information, Microsoft/System/Microsoft.AspNetCore = Warning, Microsoft.Hosting.Lifetime = Information), relative log paths go to the app directory; a normal start of the web host logs no Warning or higher (in-memory sink) |
| `EndToEnd/ServerInfoTests` | end-to-end (SSH.NET) + unit | `ServerInfo` (admin UI): each host key fingerprint equals the one SSH.NET receives, unreadable keys give an error text, the offered algorithms, user key fingerprints |
| `WebUi/SettingsPagesTests` | bUnit | server settings page: loads and saves (other settings stay), port and bind address validation, the override notes for `SshServer:Port` / `SshServer:BindToAddress`, host key fingerprints without the private key, direct-tcpip warning; IP access page: saves blacklist, whitelist and auto-ban settings, rejects invalid CIDR entries, lists the active bans and unbans one, expired bans |
| `WebUi/UsersPageTests` | bUnit | users page: list and search, create with a hashed password and a whitelist, invalid CIDR, user name and password are rejected, missing root directory warning, edit keeps the password, last login and key fingerprint, delete only after confirmation, key generation (stored public key, downloaded private key), key removal, the permission and path filter tables (default `/` = all, edit, add, remove, invalid paths and patterns) |
| `WebUi/AdminUiPagesTests` | in-memory web host | after a login every page renders (prerendered) with the stored users, settings and bans; `/access` needs a login; the local Bootstrap, icon and script files are served without a login; `blazor.web.js` is served; Radzen is not referenced; with `SshServer:Port` / `SshServer:BindToAddress` configured, the settings page and the dashboard show the override |
| `EndToEnd/ZeroConfigStartTests` | end-to-end (process, SSH.NET) | the built `ServerConsoleApp` starts from a copy of its build output in an empty temp directory with only `--port`: it creates `freesftpsharp.db` with the RSA and ECDSA host keys and the log file itself, there is no default user, a user added with `SqlSettingsRepository.AddUser` can connect with SSH.NET, upload and list a file, and the start logs no Error or Fatal (console and log file). The comment of the class says what a new local user has to do |
| `WebUi/AdminUiAuthenticationTests` | in-memory web host (`WebApplicationFactory<Program>`) | anonymous `/`, `/users`, `/general` redirect to `/Login`; anonymous `/_blazor` negotiate/connect get 401; login with antiforgery token, wrong credentials, missing token (400), open redirect, logout, cookie flags; without a credential everything answers 503 |

Skipped tests with `Skip = "Product bug: ..."` document a known bug. Remove the `Skip` when the bug is fixed.

## Infrastructure

- `Infrastructure/SftpServerFixture` starts the real `HostedServer` in-process (derive from it and override
  `IdleTimeoutSeconds`, `ConfigureSettings`, `ConfigureUser` (for example the permissions of `test_person`) or `CreateTimeProvider` for other settings or a fake clock; `BanTracker` gives the auto-ban state; `Connections` gives the connection registry; `Repository` gives the settings, for example to add users). It picks a free port,
  creates `<temp>/root` (the user root, `/` for the client) and `<temp>/config.db` (a secret file outside the
  root, `SecretFilePath` / `SecretContent`), creates the user `test_person` / `1234`, and waits until the port
  sends the SSH identification line. It stops the server and deletes the directory afterwards.
- `Storage/InMemoryFileSystem` is an `IFileSystem` in memory with configurable capabilities. It is only in the test
  project. Use it as the backend of SFTP tests (`new SftpEngineClient(new InMemoryFileSystem())`) and to test a storage
  decorator alone.
- `Infrastructure/InMemorySettingsRepository` replaces the real settings repository in the end-to-end tests.
- `Infrastructure/TestCredentials.HashPassword` (PBKDF2, minimum iterations) and `LegacySha256Hash` (the old
  format before issue #23) are the only places that know the password hash formats. Change them there when a
  format changes. `SftpServerFixture.AddUser` and `Repository` add users to the running server and read what it stored.
- `Infrastructure/FileLinks` creates symbolic links for the tests. On Windows without the symbolic link privilege a
  directory link falls back to a junction (no privilege needed), and a test that needs a file link is skipped.
  On Linux nothing is skipped.
- `Infrastructure/OpenSshSftp` runs the `sftp` client (see below).
- `WebUi/AdminUiComponentContext` is the bUnit context for the admin UI pages: an `InMemorySettingsRepository`, the
  real `LoginBanTracker` with a `FakeTimeProvider` (`Ban(address)` bans an address), the toast service and the listen
  options. JavaScript interop is in loose mode.
- `Infrastructure/SlowDownstreamProxy` is a TCP proxy that slows down the data from the server to the client, so
  the server's channel window fills up. Disposing it drops the connection without an SSH close.
- `Sftp/SftpEngineClient` drives the upstream SFTP engine (`SftpService`) with our `SftpFileSystemAdapter` without
  SSH: it builds SFTP v3 packets and parses the responses. `Sftp/SftpEngineTestBase` gives it a `LocalFileSystem`
  on a temporary root with a secret file next to it.
- `WebUi/AdminUiFactory` hosts the FxSshSftpServer admin UI in memory. It removes the SSH `HostedServer` and
  replaces the LiteDB repository with `InMemorySettingsRepository`, so no port is opened and no `config.db` is
  written. It sets the admin credential `admin` / `AdminUiFactory.AdminPassword` through configuration.
  The web UI test classes share one xUnit collection, because `Program` sets the static Serilog logger.

## Add a test

1. Unit test: add a class under `Unit/`. Product `internal` members of `SshServerModule` are visible to the
   test project (`InternalsVisibleTo` in `SshServerModule.csproj`).
2. End-to-end test: add a `[Fact]` to an existing class under `EndToEnd/`, or add a new class with
   `IClassFixture<SftpServerFixture>` (a new class gets its own server and runs in parallel with the others).
   - `_server.Connect()` gives a connected `SftpClient`; dispose it with `using`.
   - `_server.CreateUniqueDirectory()` gives a new empty directory, so the test does not depend on other tests.
   - `_server.PhysicalPath("/dir/file")` gives the file on disk, to check what the server really wrote.
3. Storage backend: add one subclass of `Storage/FileSystemConformanceTests<TFixture>` with a fixture that gives a new,
   empty storage and the capabilities that the backend must declare. Put the checks of the physical storage in the
   tests of the backend.
4. One test for each behavior, with a name that says the behavior.

## OpenSSH requirement

`OpenSshSftpTests` run only when `sftp` (OpenSSH client) is on `PATH`; otherwise they are skipped with the
reason "OpenSSH sftp is not on PATH". GitHub Actions `ubuntu-latest` has it. On Debian/Ubuntu:
`sudo apt-get install openssh-client`.

The password comes from a generated `SSH_ASKPASS` script with `SSH_ASKPASS_REQUIRE=force` and `DISPLAY=:0`.
The commands go to stdin, because `sftp -b` turns off password authentication. The harness adds a final `lpwd`
and waits for its output; if sftp then does not exit by itself within a short time, the harness stops the
process, so a server bug cannot hang the suite. `OpenSshSftp.RunWithOptionsAsync` adds extra `-o` options, and
`RunWithArgumentsAsync` adds other sftp arguments (for example `-R`, `-B`) and connects to another port (a proxy).

On Windows the OpenSSH tests are skipped by default, because the `.cmd` askpass path is not verified there.
Set `FREESFTPSHARP_OPENSSH_ON_WINDOWS=1` to run them. Set `FREESFTPSHARP_SFTP_LOGLEVEL=DEBUG3` to see the
ssh protocol log of a failing OpenSSH test.
