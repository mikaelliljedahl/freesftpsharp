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
| `Unit/LocalFileSystemTests` | unit | `NormalizeVirtualPath` and `GetPhysicalPath` with traversal inputs (`/../../etc/passwd`, `..\..\config.db`, `/a/b/../../../../c`, `//double//slash`, `/.../x`, empty, `.`), a sibling directory with the same prefix as the root, the root cannot be removed or moved |
| `Unit/SftpSubsystemNormalizePathTests` | unit | `SftpSubsystem.NormalizePath` (the SSH_FXP_REALPATH canonical path) |
| `Unit/SftpFramingTests` | unit | `SftpSubsystem.OnInput` framing: one packet split over several calls, several packets in one call, a partial packet at the end; one response for each request |
| `Settings/SqlSettingsRepositoryTests` | unit (in-memory SQLite) | default settings of a new database, update of settings, add/get/update/remove of users with all fields, unknown users, case-insensitive duplicate usernames, persistence in a file, a database of the previous schema is migrated (new columns get their defaults, the stored values stay) |
| `Settings/LiteDbImportTests` | unit (temp files) | a `config.db` made with the LiteDB repository is imported into a new SQLite database (settings, host key, users), the file is not changed, no second import, no `config.db` gives new defaults |
| `Settings/SettingsConfigurationTests` | unit | `Settings:Provider`, `ConnectionStrings:Settings` and `Settings:LiteDbPath`: defaults, paths relative to the app directory, LiteDb selection, unknown provider, `AddSshServerSettings` registrations |
| `Settings/ListenConfigurationTests` | unit | `SshServer:Port` / `SshServer:BindToAddress`: options binding (array, comma separated, `--port`/`--bind` switch mappings), precedence configuration over the stored settings (stored settings unchanged), port validation 1-65535 |
| `EndToEnd/ConfiguredPortTests` | end-to-end (SSH.NET) | the stored port is 1, the configured port is a free one: SSH.NET connects on the configured port, nothing listens on the stored port, the stored setting is not changed |
| `Unit/HostKeysTests` | unit | the stored RSA host key (base64 CSP blob or PEM) converts to PEM with the same key, a public-only blob is rejected, host key algorithms are ecdsa-sha2-nistp256, rsa-sha2-512, rsa-sha2-256 (no ssh-rsa), an ECDSA key is made once and saved |
| `Unit/UserLogicsTests` | unit | public key check by SHA-256 fingerprint, IP whitelist (also for IPv4-mapped IPv6 addresses) |
| `Unit/SessionTimeoutsTests` | unit | `IdleTimeout` gives an inactivity timeout, or keepalive probes when it is 0 |
| `EndToEnd/SshNetAuthenticationTests` | end-to-end (SSH.NET) | connect, wrong password is rejected, `Disconnect` does not wait for a timeout |
| `EndToEnd/SshNetPasswordMigrationTests` | end-to-end (SSH.NET) | login of a user with an old SHA-256 hash, the stored hash is PBKDF2 afterwards and the next login works; wrong password; PBKDF2 user; unknown user |
| `EndToEnd/PublicKeyAndWhitelistTests` | end-to-end (SSH.NET) | public key login, another key and a user without a key are rejected, unknown user, IP whitelist allows and rejects |
| `EndToEnd/AlgorithmNegotiationTests` | end-to-end (raw KEXINIT, SSH.NET) | the server's KEXINIT has no weak algorithms (ssh-rsa, *-sha1 kex, CBC, hmac-md5/sha1) and has curve25519, AES-GCM/CTR, hmac-sha2(-etm); SSH.NET connects with each host key algorithm and fails with only ssh-rsa or group1-sha1 |
| `EndToEnd/IdleTimeoutTests` | end-to-end | with `IdleTimeout` = 1 s, a client that sends nothing and an idle SFTP session are disconnected |
| `EndToEnd/SshNetFileOperationTests` | end-to-end (SSH.NET) | mkdir, 3 MB upload/download with byte compare, list, stat of file and directory, missing paths, overwrite with a smaller file, empty file, append, rename, delete, rmdir, the session survives a failed open |
| `EndToEnd/SshNetPathTraversalTests` | end-to-end (SSH.NET) | `/../config.db` cannot be read, an upload to `/../x` lands in the user root, `ListDirectory("/..")` lists the root |
| `EndToEnd/OpenSshSftpTests` | end-to-end (OpenSSH `sftp`) | put/get of 2 MB, 200 B and 0 B files, ls, rename, rm, rmdir, `cd ../..` + `pwd`, overwrite 2 MB with 200 B, `get ../../config.db` fails, sftp exits by itself, connect with the OpenSSH default algorithms (no `+ssh-rsa`), a known_hosts entry with the old `ssh-rsa` key still matches, only-weak-algorithm clients cannot connect |
| `Unit/PasswordHasherTests`, `Unit/AdminCredentialValidatorTests` | unit | the shared PBKDF2 password hash (`SshServer.Interfaces.Security.PasswordHasher`): round trip, wrong password, tampered salt/key/iterations, malformed and plaintext values; admin user name check |
| `Unit/UserPasswordVerificationTests` | unit | SFTP user passwords (`UserLogics.VerifyUserPassword`): PBKDF2 and old SHA-256 hashes, correct and wrong passwords, tampered hashes, the old hash is upgraded to PBKDF2 once and the upgrade is logged without the password |
| `Unit/CidrNotationTests` | unit | the shared CIDR helper: IPv4/IPv6 networks and single addresses, host bits, IPv4-mapped IPv6, invalid input (prefix out of range, host names, scope ids, short IPv4 forms), matching |
| `Unit/LoginBanTrackerTests` | unit | auto-ban after N failures in a sliding window, the ban expires, loopback exemption, IPv4-mapped addresses, 0 = off, `Unban`, clean-up of old records, defaults (`FakeTimeProvider`) |
| `Unit/IpFilterTests` | unit | global blacklist, global whitelist mode (empty list = no check), blacklist wins, banned addresses |
| `Unit/SecurityRegistrationTests` | unit | `AddSshServerSecurity`: `HostedServer` and `IIpBanService` share one `LoginBanTracker` |
| `EndToEnd/IpFilterAndBanTests` | end-to-end (SSH.NET, raw TCP) | a blacklisted / not whitelisted client gets no identification line; ban after 3 wrong passwords or unknown users (loopback exemption off), the ban expires (fake clock), `Unban`; `LastSuccessfulLogin` is set only on success |
| `EndToEnd/BindToAddressTests` | end-to-end (raw TCP) | `BindToAddress` = 127.0.0.1 answers on 127.0.0.1 and refuses ::1; without it both answer (the IPv6 checks are skipped when the machine has no ::1) |
| `Unit/LoginThrottleTests` | unit | lockout after N failed logins, the lockout ends, success clears the failures (`FakeTimeProvider`) |
| `Unit/AdminPasswordCommandTests` | unit | `--hash-admin-password` prints a hash that verifies, rejects short passwords |
| `WebUi/AdminUiAuthenticationTests` | in-memory web host (`WebApplicationFactory<Program>`) | anonymous `/`, `/users`, `/general` redirect to `/Login`; anonymous `/_blazor` negotiate/connect get 401; login with antiforgery token, wrong credentials, missing token (400), open redirect, logout, cookie flags; without a credential everything answers 503 |

Skipped tests with `Skip = "Product bug: ..."` document a known bug. Remove the `Skip` when the bug is fixed.

## Infrastructure

- `Infrastructure/SftpServerFixture` starts the real `HostedServer` in-process (derive from it and override
  `IdleTimeoutSeconds`, `ConfigureSettings` or `CreateTimeProvider` for other settings or a fake clock; `BanTracker` gives the auto-ban state; `Repository` gives the settings, for example to add users). It picks a free port,
  creates `<temp>/root` (the user root, `/` for the client) and `<temp>/config.db` (a secret file outside the
  root, `SecretFilePath` / `SecretContent`), creates the user `test_person` / `1234`, and waits until the port
  sends the SSH identification line. It stops the server and deletes the directory afterwards.
- `Infrastructure/InMemorySettingsRepository` replaces the real settings repository in the end-to-end tests.
- `Infrastructure/TestCredentials.HashPassword` (PBKDF2, minimum iterations) and `LegacySha256Hash` (the old
  format before issue #23) are the only places that know the password hash formats. Change them there when a
  format changes. `SftpServerFixture.AddUser` and `Repository` add users to the running server and read what it stored.
- `Infrastructure/OpenSshSftp` runs the `sftp` client (see below).
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
3. One test for each behavior, with a name that says the behavior.

## OpenSSH requirement

`OpenSshSftpTests` run only when `sftp` (OpenSSH client) is on `PATH`; otherwise they are skipped with the
reason "OpenSSH sftp is not on PATH". GitHub Actions `ubuntu-latest` has it. On Debian/Ubuntu:
`sudo apt-get install openssh-client`.

The password comes from a generated `SSH_ASKPASS` script with `SSH_ASKPASS_REQUIRE=force` and `DISPLAY=:0`.
The commands go to stdin, because `sftp -b` turns off password authentication. The harness adds a final `lpwd`
and waits for its output; if sftp then does not exit by itself within a short time, the harness stops the
process, so a server bug cannot hang the suite. `OpenSshSftp.RunWithOptionsAsync` adds extra `-o` options.

On Windows the OpenSSH tests are skipped by default, because the `.cmd` askpass path is not verified there.
Set `FREESFTPSHARP_OPENSSH_ON_WINDOWS=1` to run them. Set `FREESFTPSHARP_SFTP_LOGLEVEL=DEBUG3` to see the
ssh protocol log of a failing OpenSSH test.
