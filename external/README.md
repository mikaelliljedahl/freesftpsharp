# Vendored libraries

## FxSsh (`external/FxSsh`)

[Aimeast/FxSsh](https://github.com/Aimeast/FxSsh), vendored with `git subtree --squash` from branch `dev`
at commit `cd35224` (`fix: release forwarded sockets rejected before the bridge subscribed`). License: MIT,
see `external/FxSsh/LICENSE.md`.

Only the library project `external/FxSsh/FxSsh/FxSsh.csproj` is in `FreeSftpSharp.sln`. The upstream test
projects (`FxSsh.Tests`, `FxSsh.IntegrationTests`, MSTest) and `SshServerLoader` are not built by our
solution. `external/FxSsh/global.json` only applies to `dotnet` commands that run inside `external/FxSsh`.

### Local patches

Keep the directory identical to upstream if possible: put our code in `SshServerModule`, and send fixes
upstream. If a local patch is necessary, make it in a separate commit after the subtree commit that changes
only `external/FxSsh`, and list it here, so that the next `git subtree pull` can check it. Remove a patch
from the list when upstream has it.

| Commit subject | Files | What and why |
| --- | --- | --- |
| `FxSsh: write both fields of the uid/gid and atime/mtime pairs in SFTP ATTRS` | `FxSsh/Services/Sftp/SftpFileAttributes.cs` | `Flags` announces uid+gid (or atime+mtime) when one of them is set, but `Write` wrote only the set field, so the ATTRS was 4 bytes short. `Write` now writes 0 for the missing field of a pair. Test: `tests/FreeSftpSharp.Tests/Sftp/SftpFileAttributesTests`. |
| `FxSsh: send the outbound SFTP packets of an attached channel in order` | `FxSsh/Services/Sftp/SftpService.cs` (`Attach`) | One fire-and-forget `SendDataAsync` per packet interleaved the chunks of several packets when they waited for the same WINDOW_ADJUST (OpenSSH: "Received message too long"). `Attach` now queues the packets and sends them from one pump task; on the peer's EOF it sends the queued responses before EOF and CLOSE. Test: `OpenSshSftpTests.Get_over_a_slow_connection_with_many_requests_in_flight_gives_the_same_bytes`. |
| `FxSsh: close the SFTP handles when an attached channel is force-closed` | `FxSsh/Services/Sftp/SftpService.cs` (`Attach`, `CloseAllHandles`) | A lost connection gives no CHANNEL_CLOSE, so the open files stayed open until finalization. `Attach` releases the handles on `Channel.ForceClosed`; `CloseAllHandles` continues when one handle fails to close. Test: `SftpSessionTeardownTests`. |
| `FxSsh: log expected SFTP request failures below error level` | `FxSsh/Services/Sftp/SftpService.cs` (`ProcessRequest`, `LogFailedRequest`) | Every failed request was logged at Fail with the stack trace in the message, also a STAT of a missing path (clients probe paths all the time). Missing path, denied access and bad requests are now logged at Debug, other I/O failures (FAILURE from file operations) at Info, and only unexpected exceptions at Fail, with the exception object. Test: `tests/FreeSftpSharp.Tests/Sftp/SftpFailureLoggingTests`. |

Upstream gaps that our code handles, so no local patch is needed (candidates for upstream pull requests in
upstream's own `LocalFileSystem`, which we do not use):

- `LocalFileSystem.RemoveFile` of a missing file answers OK (`File.Delete` does not throw); it must be
  SSH_FX_NO_SUCH_FILE. `SftpFileSystemAdapter.RemoveFile` does this.
- `LocalFileSystem` SETSTAT/FSETSTAT ignore the permissions. `SftpFileSystemAdapter` applies them through
  `IFileSystem.SetPermissions`.
- The engine sends the exception message to the client in the STATUS message; upstream's `LocalFileSystem`
  exceptions contain physical paths. `SftpFileSystemAdapter` replaces every exception with one that has only
  the virtual path.

### Update

```sh
git subtree pull --prefix=external/FxSsh https://github.com/Aimeast/FxSsh.git dev --squash
```

Then build and run the full test suite. Upstream targets the newest .NET (net11.0 at `cd35224`); our
projects must target the same version or newer.
