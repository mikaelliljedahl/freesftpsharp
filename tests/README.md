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
| `EndToEnd/SshNetAuthenticationTests` | end-to-end (SSH.NET) | connect, wrong password is rejected |
| `EndToEnd/SshNetFileOperationTests` | end-to-end (SSH.NET) | mkdir, 3 MB upload/download with byte compare, list, stat of file and directory, missing paths, overwrite with a smaller file, empty file, append, rename, delete, rmdir, the session survives a failed open |
| `EndToEnd/SshNetPathTraversalTests` | end-to-end (SSH.NET) | `/../config.db` cannot be read, an upload to `/../x` lands in the user root, `ListDirectory("/..")` lists the root |
| `EndToEnd/OpenSshSftpTests` | end-to-end (OpenSSH `sftp`) | put/get of 2 MB, 200 B and 0 B files, ls, rename, rm, rmdir, `cd ../..` + `pwd`, overwrite 2 MB with 200 B, `get ../../config.db` fails |

Skipped tests with `Skip = "Product bug: ..."` document a known bug. Remove the `Skip` when the bug is fixed.

## Infrastructure

- `Infrastructure/SftpServerFixture` starts the real `HostedServer` in-process. It picks a free port,
  creates `<temp>/root` (the user root, `/` for the client) and `<temp>/config.db` (a secret file outside the
  root, `SecretFilePath` / `SecretContent`), creates the user `test_person` / `1234`, and waits until the port
  sends the SSH identification line. It stops the server and deletes the directory afterwards.
- `Infrastructure/InMemorySettingsRepository` replaces the LiteDB `SettingsRepository` (which always opens
  `config.db` in the current directory).
- `Infrastructure/TestCredentials.HashPassword` is the only place that knows the password hash format. Change it
  there when the format changes.
- `Infrastructure/OpenSshSftp` runs the `sftp` client (see below).

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
The commands go to stdin, because `sftp -b` turns off password authentication. Because of a known server bug
(the server does not close the SFTP channel after the client's EOF), sftp does not exit by itself; the harness
waits for the output of a final `lpwd` and then stops the process.

On Windows the OpenSSH tests are skipped by default, because the `.cmd` askpass path is not verified there.
Set `FREESFTPSHARP_OPENSSH_ON_WINDOWS=1` to run them. Set `FREESFTPSHARP_SFTP_LOGLEVEL=DEBUG3` to see the
ssh protocol log of a failing OpenSSH test.
