# WebDAV server

The web host (`FxSshSftpServer`) can offer the same users and storage over WebDAV (issue #71), so that Windows
Explorer, macOS Finder, GNOME Files, rclone and backup tools can use the server as a network drive, also where port 22
is blocked. WebDAV is a plug-in (`FreeSftpSharp.WebDav`, `AddWebDav()` and `MapWebDav()`) and is **off by default**:
without configuration the host maps no WebDAV path and opens no port. `ServerConsoleApp` has no web server and no WebDAV.

## Turn it on

```json
{
  "WebDav": {
    "Enabled": true
  }
}
```

The user root is then at `https://<server>/dav/` on the endpoints of the web host. Every WebDAV request goes through
the user's file system with all its rules: permissions and path filters (#59), virtual folders (#56), quotas and
bandwidth limits (#62), and the events of the audit log, webhooks and event rules (#65, protocol `WebDAV`).

| Setting | Default | Effect |
|---|---|---|
| `WebDav:Enabled` | `false` | Turns WebDAV on. |
| `WebDav:Path` | `/dav` | The URL path of the user root. `/` needs `WebDav:Port`. |
| `WebDav:Port` | `0` | 0: WebDAV answers under `Path` on every endpoint. A port: WebDAV answers only on that local port, and every request to it is a WebDAV request (the admin UI is not reachable there). |
| `WebDav:AllowInsecureHttp` | `false` | Allow Basic authentication over plain HTTP from other hosts than loopback. |
| `WebDav:Realm` | `FreeSftpSharp` | The realm of the Basic challenge. |
| `WebDav:SessionIdleTimeoutSeconds` | `300` | A session (one connection, one login event) ends after this time without a request. |
| `WebDav:DefaultLockTimeoutSeconds` | `600` | The lock timeout when the client asks for none or for `Infinite`. |
| `WebDav:MaxLockTimeoutSeconds` | `3600` | The longest lock timeout. |
| `WebDav:MaxUploadBytes` | none | The largest PUT body. Empty: no protocol limit (the quota of the user still applies). |

### HTTPS and an own port

WebDAV uses HTTP Basic authentication, so the password is in every request. The server refuses Basic over plain HTTP
(403) unless the client is on loopback or `WebDav:AllowInsecureHttp` is set. Give it a Kestrel endpoint with a
certificate, for example its own port with the user root at `/`:

```json
{
  "Kestrel": {
    "Endpoints": {
      "Http": { "Url": "http://localhost:5000" },
      "WebDav": {
        "Url": "https://*:8443",
        "Certificate": { "Path": "/etc/freesftpsharp/webdav.pfx", "Password": "<from a secret store>" }
      }
    }
  },
  "WebDav": { "Enabled": true, "Port": 8443, "Path": "/" }
}
```

Behind a TLS proxy, configure the ASP.NET Core forwarded headers (`ForwardedHeadersOptions`, with the proxy as a known
proxy), so that the request counts as HTTPS; do not use `AllowInsecureHttp` for that.

## Users

- **Login.** HTTP Basic with the user name and password (UTF-8). The rules are the ones of the SFTP login, in one
  place (`PasswordLoginService`): the global IP rules and the auto-ban (a wrong password counts as a failed login), the
  IP whitelist of the user, the PBKDF2 password and `AllowedAuthMethods` (the password must be allowed). Digest is not
  implemented.
- **Protocols.** `User.AllowedProtocols` (admin UI: user form, "Protocols"; default: all) says which protocols a user
  may use. A user without WebDAV gets 403, but only after a correct password, so a client without the password learns
  nothing. SFTP refuses a user without SFTP like a wrong password.
- **App passwords.** A WebDAV client cannot answer a second login step. A user with a multi-step login
  (`RequireAllOf`) or a TOTP second factor (#63) cannot log in to WebDAV with the password alone; give it an app
  password (admin UI: user form, "App passwords"). An app password is random (28 characters, about 160 bits), valid for
  the protocols that you select, can expire, and is shown once; the server keeps only its SHA-256 hash. An app password
  for SFTP is a password of the SFTP login (it does not replace a TOTP code there).
- **Sessions.** HTTP has no connection. The server keeps a session per client address and credential: the password is
  checked once (PBKDF2), the admin UI page "Connections" and the metrics show one WebDAV connection, and the audit log
  has one `LoginOk` and one `Logout`. A session ends after `SessionIdleTimeoutSeconds`, when an administrator
  disconnects it, or when the stored user changes (for example a new password or other permissions).

## Protocol

Class 1 and 2 of RFC 4918:

- `OPTIONS`, `GET` and `HEAD` (single byte ranges, `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Range`; an
  HTML listing for a collection), `PUT` (streamed to the storage in order, so it works on object stores),
  `DELETE`, `MKCOL`, `COPY` and `MOVE` (`Destination`, `Overwrite`, `Depth`), `LOCK` and `UNLOCK`, `PROPFIND`
  (depth 0 and 1) and `PROPPATCH`.
- The entity tag is made from the size and the modification time.
- `PROPFIND` with depth infinity is refused (403 `propfind-finite-depth`, as RFC 4918 allows).
- `PROPPATCH` sets only the modification time (`DAV:getlastmodified`, `Win32LastModifiedTime`) and the access time
  (`Win32LastAccessTime`), on a storage with `SetTimes`. `Win32CreationTime` and `Win32FileAttributes`, which Windows
  sends after each copy, are accepted and not kept. The storage has no dead properties: every other property gets 403
  and the whole update fails (424 for the others).
- Locks are write locks (exclusive or shared, depth 0 or infinity) in memory, with timeouts; a restart forgets them.
  Each user has its own locks. A lock on an unmapped URL creates an empty file. A change of a locked resource, of a
  member of a locked collection or of the membership of a locked collection needs the lock token in the `If` header,
  otherwise 423.
- `MOVE` uses the rename of the storage. When the storage cannot do it (a storage without `Rename`, or a move between
  two virtual folders) the answer is 502. `COPY` copies the data through the server, so it works everywhere.
- A URL with a `.` or `..` segment, an encoded `/` or `\`, or a NUL is refused (403), never normalized.

### Why not NWebDav

The issue asked to evaluate `NWebDav` as a base. Its repository (ramondeklein/nwebdav, MIT) is archived since 2024, the
last stable package (0.1.36) is from 2021, and there is only a 0.2 beta. So the methods are implemented here, on
ASP.NET Core and `IFileSystem`, without a new dependency.

## Clients

- **Windows Explorer.** Map a network drive to `https://server:8443/` (or `\\server@SSL@8443\DavWWWRoot`). Windows
  sends Basic only over HTTPS and needs a certificate that it trusts. A dedicated port with `Path` `/` works best:
  the Windows WebClient also asks the server root. Files larger than about 50 MB need a larger
  `FileSizeLimitInBytes` of the WebClient service (registry `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters`).
- **macOS Finder.** Go, Connect to Server, `https://server:8443/`. Finder locks files while it writes them; the locks
  are supported.
- **Linux.** GNOME Files: `davs://server:8443/`. KDE Dolphin: `webdavs://server:8443/`. davfs2:
  `mount -t davfs https://server:8443/ /mnt/dav`. rclone: a remote of type `webdav` with vendor `other`. cadaver:
  `cadaver https://server:8443/`.

The manual checks of the issue (mount, create a folder, copy a 100 MiB file in and out, rename it) with Windows
Explorer and macOS Finder are not automated.

## Tests

`tests/FreeSftpSharp.Tests/WebDav` runs the server in memory (TestServer) over the real storage factory and its
decorators: litmus-style tests for every method (basic, copymove, props, locks), the error codes, the login rules,
the sessions, the events and a storage without random writes. `WebDavHostTests` checks the real web host: no WebDAV by
default, a full round trip with `WebDav:Enabled`. The `litmus` suite itself does not run in CI yet.
