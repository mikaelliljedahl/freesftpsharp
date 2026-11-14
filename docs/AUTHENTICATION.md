# Authentication providers

By default the server checks every login against its own database: the password hash and the public keys of the
user. With an **authentication provider** (issue #64) the users of an organisation's directory (LDAP or Active
Directory) or of an external service log in too, and the server creates them locally at their first login ("just in
time"). Nothing changes until a provider is configured.

## How it works

- The providers run in order (`Auth:Providers`). Each one answers *success*, *failure* or *not handled*; the first
  success or failure wins, *not handled* asks the next provider. Without `Auth:Providers` the order is the database
  first, then the configured plug-ins.
- **A user belongs to one provider.** A user created by a provider has its name in `AuthenticationProvider` (shown as a
  badge in the admin UI), and only that provider checks its credential. So a directory never logs in a local user with
  the same name, and a local password never opens a directory account. A local user (created in the admin UI or with
  `user add`) is checked by the database only.
- **Just in time.** A user that is not stored is created after the provider accepted the login, with the groups (and
  optionally the permissions, networks and session limit) the provider gives. The next logins update these values. For
  an SSH public key the user is saved only after the client proved that it has the private key.
- **No local password.** The provider manages the password of its users: the web client does not offer "Change
  password" and refuses it, the admin UI disables the password fields, and the REST API refuses a `password` for such a
  user ("The password of this account is managed by ldap."). The password age never applies to them.
- **The local rules still apply.** Status, expiry, session limit, the allowed networks and login methods of the user
  and its groups, the TOTP second factor and the multi-step logins work as for a local user. Disable a user in the
  admin UI to lock it out, whatever the provider says. A refused login looks like a wrong password to the client.
- **Groups are templates.** Give the storage (for example a storage template `/srv/sftp/%username%`), the virtual
  folders and the permissions to a local group, and let the provider put its users in it. A user created by a provider
  whose groups give no storage gets `<Auth:ExternalUsers:RootDirectory>/<username>` on the local disk; without that
  setting it has no storage and its SFTP session is refused.
- **Fail closed.** A provider that cannot answer (timeout, connection error, an invalid answer) refuses the login. The
  failure is logged with the reason (never with the password), is in the audit log, and counts for the auto-ban.
- **Timing.** A login that is refused before the credential check (a disabled user, a forbidden network) takes the
  time of a wrong password: a key derivation for a local user, the mean time of the last refused logins of the
  provider for a user of a provider. The provider is not asked for such a login.

| Setting | Default | Meaning |
| --- | --- | --- |
| `Auth:Providers` | empty | The order, for example `["database", "ldap"]`. A configured provider that is not in a non-empty list is not used; an unknown name stops the start. |
| `Auth:ExternalUsers:RootDirectory` | empty | The absolute directory below which a new user of a provider gets its root directory (created at its first login). |

Put secrets (`Auth:Ldap:BindPassword`, `Auth:HttpHook:Secret`) in environment variables
(`Auth__Ldap__BindPassword=...`) or the user secrets, not in `appsettings.json`.

## LDAP and Active Directory

`AddLdapAuthentication` (project `SshServer.Authentication.Ldap`, System.DirectoryServices.Protocols). It is off until
`Auth:Ldap:Server` is set. On Linux and macOS it needs the OpenLDAP client library (`libldap`, for example the Debian
package `libldap-2.5-0` or `libldap2`); the official .NET container images do not have it.

The provider finds the user with a search (as the search account `BindDn`, or anonymously) or by its DN
(`UserDnTemplate`), checks the password with a bind as the user on its own connection, and reads the groups of the user
from `GroupAttribute` (`memberOf`) or with `GroupSearchFilter`. The user name is escaped in filters (RFC 4515) and DNs
(RFC 4514). An empty password is refused before the directory is asked (an LDAP bind with an empty password is an
anonymous bind). A user that is not in the directory is *not handled*.

| Setting | Default | Meaning |
| --- | --- | --- |
| `Server`, `Port` | -, 389 (636 with `UseTls`) | The directory server. |
| `UseTls` / `StartTls` | false | LDAPS, or StartTLS on the plain port. One of them is required, unless `AllowPlainText` is true (a test directory only: the password goes in clear text). |
| `BindDn`, `BindPassword` | empty | The search account. Empty: anonymous search (or `UserDnTemplate`). |
| `BaseDn`, `UserFilter` | -, `(&(objectClass=person)(uid={username}))` | Where and how the user is searched. |
| `UserDnTemplate` | empty | A direct bind, for example `uid={username},ou=users,dc=example,dc=org`, without a search. |
| `GroupAttribute` | `memberOf` | The attribute with the DNs of the groups of the user. |
| `GroupSearchFilter`, `GroupSearchBaseDn` | empty | A group search for a directory without `memberOf`, for example `(&(objectClass=groupOfNames)(member={dn}))`. |
| `GroupMappings` | empty | Directory group (DN or the name of its first RDN) to local group name. Empty: a directory group gives the local group with the same name. Groups without a local group are skipped. |
| `DefaultGroup` | empty | The local primary group (the template) of every directory user. Empty: the first mapped group. |
| `SshPublicKeyAttribute` | empty | The attribute with OpenSSH public keys (for example `sshPublicKey` of the openssh-lpk schema). Empty: no key login through the directory. |
| `TimeoutSeconds` | 10 | The time of one directory operation. |

OpenLDAP (users in `ou=users`, groups as `groupOfNames`):

```json
{
  "Auth": {
    "Providers": [ "database", "ldap" ],
    "ExternalUsers": { "RootDirectory": "/srv/sftp" },
    "Ldap": {
      "Server": "ldap.example.org",
      "StartTls": true,
      "BindDn": "cn=sftp-search,ou=services,dc=example,dc=org",
      "BaseDn": "ou=users,dc=example,dc=org",
      "UserFilter": "(&(objectClass=inetOrgPerson)(uid={username}))",
      "GroupAttribute": "",
      "GroupSearchBaseDn": "ou=groups,dc=example,dc=org",
      "GroupSearchFilter": "(&(objectClass=groupOfNames)(member={dn}))",
      "GroupMappings": { "sftp-staff": "staff", "sftp-partners": "partners" },
      "SshPublicKeyAttribute": "sshPublicKey"
    }
  }
}
```

Active Directory (sAMAccountName, nested groups with the matching rule `1.2.840.113556.1.4.1941`):

```json
{
  "Auth": {
    "Ldap": {
      "Server": "dc01.corp.example.com",
      "UseTls": true,
      "BindDn": "CN=svc-sftp,OU=Service Accounts,DC=corp,DC=example,DC=com",
      "BaseDn": "DC=corp,DC=example,DC=com",
      "UserFilter": "(&(objectCategory=person)(objectClass=user)(sAMAccountName={username})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
      "GroupAttribute": "",
      "GroupSearchFilter": "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={dn}))",
      "GroupMappings": { "SFTP Users": "staff" },
      "DefaultGroup": "staff"
    }
  }
}
```

## External HTTP hook

`AddHttpAuthHook` (project `SshServer.Authentication.Http`). It is off until `Auth:HttpHook:Url` is set. This is how an
organisation plugs in its own identity logic without C#, like the external authentication hook of SFTPGo.

| Setting | Default | Meaning |
| --- | --- | --- |
| `Url` | empty | The URL. `https://`, or `http://` only to localhost (the request has the password). |
| `Secret` | empty | The HMAC key of the `X-FreeSftpSharp-Signature` header (at least 16 characters), the same format as the webhooks (see [WEBHOOKS.md](WEBHOOKS.md)). |
| `TimeoutSeconds` | 10 | The time for one answer (1 to 60). |
| `PublicKeys` | true | Also ask the hook for public key logins. |

The server sends a `POST` with a JSON body (snake_case, unchanged). `password` is only in a password login, `public_key` (an
`authorized_keys` line) only in a key login. For an SSH public key the hook can be asked twice per key (OpenSSH asks
whether a key is accepted before it signs).

```json
{ "username": "alice", "method": "password", "password": "...", "ip": "192.0.2.10", "protocol": "SSH" }
```

The answer:

- `200` with a user: the login is accepted. Every field is optional; a missing field (or `null`) leaves the stored
  value. `username`, when given, must be the name of the request.

  ```json
  {
    "username": "alice",
    "primaryGroup": "staff",
    "groups": [ "partners" ],
    "permissions": { "/": [ "List", "Download" ], "/incoming": [ "List", "Upload" ] },
    "onlyWhitelistedIps": true,
    "whitelistedIps": [ "192.0.2.0/24" ],
    "maxSessions": 2,
    "description": "Partner account"
  }
  ```

  The answer is the `UserAttributes` object (`SshServer.Interfaces.Authentication`): the fields have the names and the
  JSON types of the user of the REST API (`UserView` and `UserWrite` of `/api/v1/users`, see [REST-API.md](REST-API.md)),
  so the same code can write both. Only the groups differ: the hook gives local group **names** (`primaryGroup`,
  `groups`), because it does not know the local ids; the REST API has the ids (`primaryGroupId`, `secondaryGroupIds`).
  Without `onlyWhitelistedIps`, a non-empty `whitelistedIps` list also turns it on. The answer never sets the root
  directory, the storage, the status or the expiry: the storage comes from the groups, the status and the expiry stay
  local.

  The permissions are the names of `FilePermissions` (`List`, `Download`, `Upload`, `Overwrite`, `Delete`, `Rename`,
  `CreateDirectories`, `CreateSymlinks`, `ChangeMode`, `ChangeTimes`, `All`) and need an entry for `/`. Unknown groups
  are skipped with a warning; an invalid value refuses the login.
- `204`: the hook does not know the user; the next provider is asked.

**Deprecated: the snake_case answer.** The first version of the hook answered in snake_case: `primary_group`,
`allowed_ips` and `max_sessions` (now `primaryGroup`, `whitelistedIps` and `maxSessions`; `username`, `groups`,
`permissions` and `description` have the same names in both). This release still reads it, with the same meaning as
before, and logs one warning per process at the first such answer. The next release reads only the camelCase names.
An answer that gives one field in both forms is refused.
- Anything else (`401`, `403`, `500`, a redirect), no answer within the timeout, or an answer over 64 KiB: refused.

A sample service in Python (standard library only) that checks the signature:

```python
import hashlib, hmac, json, time
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = b"a-secret-of-at-least-16-characters"
USERS = {"alice": {"password": "correct horse battery staple", "groups": ["staff"]}}

class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        parts = dict(p.split("=", 1) for p in self.headers.get("X-FreeSftpSharp-Signature", "").split(","))
        expected = hmac.new(SECRET, parts.get("t", "").encode() + b"." + body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, parts.get("v1", "")) or abs(time.time() - int(parts["t"])) > 300:
            return self.answer(401)
        request = json.loads(body)
        user = USERS.get(request["username"])
        if user is None:
            return self.answer(204)  # not ours: the next provider decides
        if not hmac.compare_digest(user["password"], request.get("password", "")):
            return self.answer(403)
        self.answer(200, {"primaryGroup": user["groups"][0], "permissions": {"/": ["All"]}})

    def answer(self, status, user=None):
        data = json.dumps(user).encode() if user is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

HTTPServer(("127.0.0.1", 8085), Hook).serve_forever()
```

```json
{ "Auth": { "Providers": [ "database", "http" ], "HttpHook": { "Url": "http://localhost:8085/auth" } } }
```

## Tests

The chain, the just-in-time users, the HTTP hook (against an in-process Kestrel receiver, also over SSH.NET) and the
LDAP provider (against an in-memory directory) are unit and end-to-end tests. The LDAP end-to-end tests run against an
OpenLDAP container when `FREESFTPSHARP_TEST_LDAP` is set (CI does it on Linux):

```bash
docker run -d -p 127.0.0.1:1389:1389 -e LDAP_ROOT=dc=example,dc=org -e LDAP_ADMIN_PASSWORD=adminpassword \
  -e LDAP_USERS=alice,bob -e LDAP_PASSWORDS=alice-password,bob-password -e LDAP_GROUP=sftp-staff bitnamilegacy/openldap:2.6.10
FREESFTPSHARP_TEST_LDAP=127.0.0.1:1389 dotnet test --filter "FullyQualifiedName~Ldap"
```
