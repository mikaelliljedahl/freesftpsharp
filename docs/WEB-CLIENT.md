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

## Share links

A user of the web client can share files and folders with people who have no account (issue #70): a **download link**
(the files, and a folder or the whole share as a zip), an **upload link** into a folder (an "inbox"), or both. It is
**off by default**: sharing needs the web client (`WebClient:Enabled`) and the server setting "Allow share links" (admin
UI, Server settings, card "Share links"; stored as `ServerSettings.Shares`). Until then every `/shares` path answers 404.

| Server setting | Default | Effect |
|---|---|---|
| Allow share links (`Shares.Enabled`) | off | The users may create share links, and the links work. Off again: no link works (they are kept). |
| Maximum lifetime (`Shares.MaxLifetimeDays`) | 0 | Every new share must expire within this many days. 0: no limit. |
| Every new share needs a password (`Shares.RequirePassword`) | off | A share without a password cannot be created. |
| `WebClient:ShareRequestsPerMinute` (configuration) | `300` | Requests per client address and minute on `/shares`; more get 429. |

### Create, list and revoke

The page **Shares** of the web client (`/client/shares`, also the share button of a file or folder) creates a share:

- a name and a description, one or more files or folders of the user (not the whole home folder), and what it allows:
  **Download**, **Upload (inbox)** (only folders) or both;
- an optional **password** (stored as a PBKDF2 hash), **expiry** (UTC), **maximum uses** (downloads and uploads; 0 is no
  limit) and **allowed client networks** (CIDR);
- whether an upload may **replace an existing file** (off by default: an existing file is never overwritten).

The page lists the shares of the user with their uses and a "Copy link" button, and revokes a share: the link stops at
once. The link is `https://<server>/shares/<id>`; the id is 160 random bits (base64url, 27 characters). Administrators see
the shares of the users in their scope on the admin page **Shares** (`/share-links`) and in the REST API
(`GET /api/v1/shares`, `DELETE /api/v1/shares/{id}`), with the permission ManageUsers, and can revoke them.

### The same rules as the owner

A visitor of a link uses the file system of the owner from `IFileSystemFactory`, with the whole decorator chain, the
protocol `HTTPShare` and the share id in `FileEvent.Metadata` (`shareId`, `shareName`):

- **Permissions** (#59): the permissions of the owner limited to the scope of the share (`ClientContext.PermissionMask`):
  a download share has at most List and Download, an upload share at most Upload (and Overwrite when the owner allowed
  replacing files). A share never does more than its owner may do now, and never delete, rename or create folders.
- **Paths**: a request may use only the shared paths and what is below them (`SharePaths`, after the normalization of
  `..`, with the case rules of the storage). Anything else is 404. Symbolic links are not followed.
- **Quotas** (#62): the disk and transfer quota and the bandwidth of the owner. A full quota refuses an upload (507).
- **Events** (#65): the downloads and uploads are file events of the owner with `Protocol = HTTPShare`, so the audit log,
  the webhooks (for example an `Upload` webhook for an inbox) and the event rules see them. A visitor is an auth event
  `LoginOk`/`Logout` (method `share:<id>`); a wrong password is `LoginFailed`.
- **Connections** (#57): one connection per share and client address (protocol `HTTPShare`, the owner as user) until it
  is idle for `WebClient:SessionIdleMinutes`. The page Connections shows it and "Disconnect" ends it. It does not count for
  the session limit of the owner.

### What a visitor gets

- `GET /shares/{id}`: the landing page with the name, the password form of a share with a password, the shared files
  and folders (a download share) and the upload area (an upload share; an inbox does not show its content).
- `GET /shares/{id}/download?path=`: a file (with byte ranges), or a folder as a zip; without `path` the whole share as
  a zip. Each download is one use.
- `POST /shares/{id}/upload/check` and `GET|POST|DELETE /shares/{id}/upload?path=&id=`: the chunked upload of the web
  client (`Content-Range`), into a shared folder. The name is checked (no `/`, `\`, `.` or `..`). Each upload is one use,
  counted at its first chunk.

### Abuse controls

- A share that cannot be used answers **404**, whatever the reason: unknown or malformed id, expired, used up (the count
  and the check are one database step), revoked, sharing off, the owner removed (a new user with the same name does not
  get the old shares), disabled, expired or without the protocol "Web client", the client address blocked by the global
  IP rules or the auto-ban, or not in the allowed networks of the share. So the ids cannot be probed.
- A wrong password counts in the login throttle of the web client (`WebClient:MaxFailedLogins` per client address, then
  `LockoutMinutes`). The right password sets an encrypted cookie for `/shares/{id}` only (HttpOnly, 12 hours).
- Every `/shares` request counts for the rate limit per client address (`WebClient:ShareRequestsPerMinute`).
- The pages and downloads have the security headers of the web client (CSP, `nosniff`, attachment with a sandbox CSP);
  an upload needs the antiforgery token of the landing page.

The shares are in the settings database (table `Shares`, removed with their user). With the obsolete LiteDB settings they
are kept in memory only.
