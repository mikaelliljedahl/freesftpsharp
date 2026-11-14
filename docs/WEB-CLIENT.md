# Web client

The web host (`FxSshSftpServer`) can offer the SFTP users a web client in the browser (issue #69): browse, upload,
download (also as a zip), rename, delete and create folders, change the password, manage the SSH public keys and the
second factor, and see the open sessions. It is for partners who have no SFTP client. It is **off by default**: without
configuration every `/client` path answers 404. `ServerConsoleApp` has no web server and no web client.

## Turn it on

```json
{
  "WebClient": {
    "Enabled": true
  }
}
```

The users log in at `https://<server>/client`. The web client needs no administrator: it also works when the admin UI
is closed because no administrator exists.

| Setting | Default | Effect |
|---|---|---|
| `WebClient:Enabled` | `false` | Turns the web client on. |
| `WebClient:AllowInsecureHttp` | `false` | Allow the web client over plain HTTP from other hosts than loopback. Without it such a request gets 403. |
| `WebClient:MaxFailedLogins` | `5` | Failed passwords and codes from one address before it is locked out (in addition to the auto-ban of the server). |
| `WebClient:LockoutMinutes` | `15` | The lockout time. |
| `WebClient:SessionIdleMinutes` | `30` | A browser session ends after this time without a request. |
| `WebClient:UploadChunkBytes` | `8388608` | The size of one upload request (8 MiB). At most 28 MiB (the request body limit of Kestrel is 30 MB). |
| `WebClient:UploadIdleMinutes` | `30` | An unfinished upload is aborted after this time without a chunk. |
| `WebClient:MaxUploadsPerSession` | `16` | Unfinished uploads of one session at the same time. |

Each user also needs the protocol "Web client" (`User.AllowedProtocols`, flag `Web`, on the Users page under
Protocols). Users that allow all protocols (the default) have it.

## The same rules as SFTP

Every action of the browser goes through the file system of the user from `IFileSystemFactory`, with the whole decorator
chain and the protocol `HTTP`:

- **Permissions and path filters** (#59, with the groups #61). The page shows only the controls that the permissions
  of the folder allow (a folder with only `Upload` shows the upload button and no download, delete or list), and the
  endpoints are refused by the permission decorator in any case: a crafted request gets 403.
- **Quotas** (#62). Before an upload starts, the browser asks `/client/api/upload/check`, which compares the size with
  the free space of the quota, so the user gets a clear message before the first byte. The first chunk checks it again,
  and every write is checked by the quota decorator.
- **Events** (#65). Every action is in the audit log, the webhooks and the event rules with `Protocol = HTTP`; the
  logins and logouts are auth events with `Protocol = HTTP`.
- **Connections** (#57). Each browser login is one connection of the connection registry (protocol `HTTP`): the admin
  page Connections shows it with its transfers, the session limit of the user counts it, and "Disconnect" ends it.

## Login

The login uses the `PasswordLoginService` of the protocols (the global IP rules, the auto-ban, the lifecycle of the user,
its allowed networks and methods, the protocol flag), in its interactive mode: unlike WebDAV, a user with a TOTP second
factor (#63) is asked for the code on a second page, and a user with an expired password (#61) can log in only to set a
new one. App passwords are not accepted in the browser (they are for programs and would skip the second factor). A user
with a multi-step login (for example key and password) cannot use the web client.

The login cookie (`.FxSshSftpServer.Client`) has its own scheme (`UserAuth`) and the path `/client`. It is HttpOnly and
SameSite=Strict. An admin cookie does not open `/client`, and a client cookie does not open the admin UI. The cookie
is checked on each request against the connection registry and a stamp of the user (password, status), so a logout, a
new password, a disabled user or a "Disconnect" of an administrator ends the session at once. The sessions are in
memory and per node: with several nodes, use sticky sessions for `/client`.

## Upload and download

- **Upload**: `POST /client/api/upload?path=&id=` with `Content-Range: bytes first-last/total`, one chunk per request
  (`UploadChunkBytes`). The first chunk opens the file through the decorator chain; every chunk is written at once with
  `IFileHandle.WriteAsync` in blocks of 256 KiB, so a file never lands in memory or in a temporary file. The last chunk
  closes the file (the upload event). The chunks come in order; `GET /client/api/upload?path=&id=` returns the offset
  that the server has, so the browser continues an interrupted upload there.
- **Download**: `GET /client/api/download?path=` streams the file with `Content-Length` and `Accept-Ranges`, and answers
  one byte range with 206, so downloads can resume.
- **Zip**: `POST /client/api/zip` (form fields `path`) streams the selected files and folders as one zip archive,
  without a temporary file.

## Security

- Every request that changes something needs the antiforgery token (the forms, or the header `RequestVerificationToken`).
- The pages send a strict `Content-Security-Policy` (only scripts and styles of the server, no inline script),
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, no referrer and no caching.
- A download is always `Content-Disposition: attachment` with `application/octet-stream`, `nosniff` and a sandbox CSP.
  The web client never shows the content of a user file in the page, so an uploaded HTML file cannot run script.
- Failed logins count for the lockout of the web client and for the auto-ban of the server.
