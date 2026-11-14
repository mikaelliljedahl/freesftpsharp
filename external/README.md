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
| `FxSsh: announce and serve the OpenSSH SFTP extensions` | `FxSsh/Services/Sftp/SftpService.cs` (`SendInit`, `ProcessExtended`), new `FxSsh/Services/Sftp/SftpExtensions.cs` | Upstream answers every SSH_FXP_EXTENDED with OP_UNSUPPORTED and announces nothing in VERSION. The engine now announces and serves `limits@openssh.com` and `expand-path@openssh.com` ("~" and "~/..." are the default directory "/", "~user" gives NO_SUCH_FILE), and `posix-rename@openssh.com`, `statvfs@openssh.com` and `fsync@openssh.com` only when the file system implements the new optional interfaces `ISftpPosixRenameFileSystem`, `ISftpStatVfsFileSystem` and `ISftpFsyncFileSystem` (upstream's own `LocalFileSystem` does not, so it announces only the first two). Read-only mode denies posix-rename and fsync and sets ST_RDONLY in statvfs. `hardlink@openssh.com` and the other extensions stay OP_UNSUPPORTED. Candidate for an upstream pull request. Test: `tests/FreeSftpSharp.Tests/Sftp/SftpExtensionTests`. |
| `FxSsh: answer NotSupportedException of the file system with SSH_FX_OP_UNSUPPORTED` | `FxSsh/Services/Sftp/SftpService.cs` (`MapException`, `LogFailedRequest`) | A `NotSupportedException` of the file system gave SSH_FX_FAILURE. A storage backend that cannot do an operation (for example a random-access write on an object store, #51) must answer SSH_FX_OP_UNSUPPORTED. It is now mapped to OP_UNSUPPORTED and logged at Debug. Candidate for an upstream pull request. Test: `tests/FreeSftpSharp.Tests/Sftp/SftpInMemoryStorageTests`, `SftpFailureLoggingTests`. |
| `FxSsh: drop the queued channel messages after the connection service is closed` | `FxSsh/Services/ConnectionService.cs` (`MessageLoopAsync`) | The channel messages are handled in a queue on another task, and `ReadAllAsync` still returns the queued messages after `CloseService`. OpenSSH sends CHANNEL_CLOSE and DISCONNECT right after each other; when the queue was late, `CloseService` had already removed the channels, the CHANNEL_CLOSE gave "Invalid server channel id" and every normal close could log `Connection service message handling failed` at Fail (#100). The loop now drops the queued messages after `CloseService` (the channels are force-closed, so the SFTP handles are released, and no reply can reach the peer) and logs an exception at Debug when the service was closed during the dispatch. A failure in an open session is still logged at Fail. Candidate for an upstream pull request. Test: `tests/FreeSftpSharp.Tests/EndToEnd/SessionCloseLoggingTests`. |
| `Abort an unfinished upload when the SFTP session is lost (#101)` | `FxSsh/Services/Sftp/ISftpFileSystem.cs` (`ISftpFileHandle.Abort`), `FxSsh/Services/Sftp/SftpService.cs` (`CloseAllHandles`) | A handle that is still open when the session ends or is lost was closed like a normal SSH_FXP_CLOSE, so an object store (S3 multipart upload) stored a partial file. `ISftpFileHandle` has a new default method `Abort()` that calls `Dispose()`; the engine calls it for the handles that are still open at session close, and SSH_FXP_CLOSE still closes normally. `SftpFileSystemAdapter` maps it to `IFileHandle.AbortAsync`. Test: `tests/FreeSftpSharp.Tests/Storage/FileHandleAbortTests`, S3 end-to-end `Lost_connection_during_an_upload_leaves_no_object_and_no_multipart_upload`. |
| `FxSsh: partial success in SSH_MSG_USERAUTH_FAILURE for multi-step authentication` | `FxSsh/Services/UserauthService.cs`, `FxSsh/Services/UserauthArgs.cs`, `FxSsh/Messages/Userauth/FailureMessage.cs` | Upstream always answers "password,publickey" with partial success = false, so a server cannot ask for a second method (RFC 4252 section 5.1). The `UserAuth` handler can now set `UserAuthArgs.PartialSuccess` with `Result`: once the credentials are verified (for "publickey" after the signature check) the service raises the new `PartialSucceed` event and answers SSH_MSG_USERAUTH_FAILURE with partial success = true instead of SUCCESS; no service is started. The new `UserAuthService.AuthenticationsThatCanContinue` sets the method list of every failure (default "password,publickey", as before). Candidate for an upstream pull request. Tests: `FxSsh.Tests` `UserAuthServiceTests` (partial success for password and publickey, only after a valid signature; the method list) and `MessageParseTests`, `tests/FreeSftpSharp.Tests/EndToEnd/MultiStepAuthenticationTests` (SSH.NET and OpenSSH). |
| `FxSsh: log imported custom algorithms at Info instead of Warn` | `FxSsh/SshServer.cs` (`LogCipherSuites`) | Upstream logs every algorithm registered through `AlgorithmCollectionBuilder.Add` at Warn ("Imported custom algorithms: ..."). Our server registers ssh-ed25519 for user keys (#58) that way, so every normal start logged a warning. A custom algorithm is a choice of the host, so it is now logged at Info; obsolete algorithms stay at Warn. Candidate for an upstream pull request. Test: `FxSsh.Tests` `LogTests.Custom_algorithms_are_logged_at_info_not_warn`. |

Upstream gaps that our code handles, so no local patch is needed (candidates for upstream pull requests in
upstream's own `LocalFileSystem`, which we do not use):

- `LocalFileSystem.RemoveFile` of a missing file answers OK (`File.Delete` does not throw); it must be
  SSH_FX_NO_SUCH_FILE. `SftpFileSystemAdapter.RemoveFile` does this.
- `LocalFileSystem` SETSTAT/FSETSTAT ignore the permissions. `SftpFileSystemAdapter` applies them through
  `IFileSystem.SetAttributesAsync`.
- The engine sends the exception message to the client in the STATUS message; upstream's `LocalFileSystem`
  exceptions contain physical paths. `SftpFileSystemAdapter` replaces every exception with one that has only
  the virtual path.

### Update

```sh
git subtree pull --prefix=external/FxSsh https://github.com/Aimeast/FxSsh.git dev --squash
```

Then build and run the full test suite. Upstream targets the newest .NET (net11.0 at `cd35224`); our
projects must target the same version or newer.
