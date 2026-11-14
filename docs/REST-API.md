# REST API v1

The REST API (#67) is the control plane of the server: provisioning from an identity system, infrastructure as code,
scripts and monitoring without the web UI. It runs in the admin web host (`FxSshSftpServer`) under `/api/v1`, and
it uses the same application services as the admin UI, so the permissions and the scope roles of the administrators
(#60) apply in the same way. The code is in `SshServer.Api` (`AddRestApi()` and `MapRestApi()`).

The OpenAPI 3 document is at `/api/v1/openapi.json` (it needs a login, like every route) and is committed as
[openapi.json](openapi.json). A test compares the two, so CI fails when the API changes and the file is not updated
(see "Change the API" below).

## Turn it on

The API is off by default. Turn it on in `appsettings.json` or with environment variables:

| Setting | Default | Effect |
|---|---|---|
| `Api:Enabled` | `false` | Maps the routes under `/api/v1`. When it is false, the routes do not exist. |
| `Api:TokenLifetimeMinutes` | `20` | The lifetime of a bearer token (1 to 1440). |
| `Api:TokenRequestsPerMinute` | `10` | Requests per minute and client address to `POST /api/v1/token`. |
| `Api:AnonymousRequestsPerMinute` | `60` | Requests per minute and client address to `GET /api/v1/health`. |

```bash
export Api__Enabled=true
```

Use HTTPS in front of the API (see "Expose the UI" in the README): tokens and API keys are credentials.

## Authentication

Every route needs an administrator, except `GET /api/v1/health` (it only says that the API answers; readiness is
`/readyz` of the observability settings) and `POST /api/v1/token`. The login cookie of the admin UI is never accepted
by the API, so a browser session cannot be used for cross-site requests to it.

### Bearer token (interactive administrators)

`POST /api/v1/token` with the name and password of an administrator gives a JWT. The failed logins count against the
same lockout as the login page (`AdminAuth:MaxFailedLogins`, `AdminAuth:LockoutMinutes`), and every login is in the
audit log (protocol `API`). An administrator who must change its password logs in to the admin UI first.

```bash
TOKEN=$(curl -s https://sftp.example.com/api/v1/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}' | jq -r .accessToken)

curl -s https://sftp.example.com/api/v1/status -H "Authorization: Bearer $TOKEN"
```

The token has the same claims as the login cookie, and every request checks them against the stored administrator:
a new password, other permissions, another scope or a disabled account ends every token at once.
`POST /api/v1/token/refresh` gives a new token for a valid one. The signing key (HMAC-SHA256) is made at the first use
and stored in the settings database, encrypted with the data protection keys (`DataProtection:KeysPath`), so several
nodes that share the database and the key ring accept each other's tokens.

With `Auth:Oidc:Admin:DisableLocalLogin` (single sign-on only, [OIDC.md](OIDC.md)) there is no password login: `POST
/api/v1/token` answers 403 with a problem text ("The password login of the administrators is turned off ... Use an API
key"), also for the right password. API keys keep working, and so does `POST /api/v1/token/refresh` for a token that
is still valid.

An administrator with a second factor (#63) gives its TOTP code, or one of its recovery codes, in `totpCode`; without a
valid code there is no token. The check is the same as on the login page (`ITwoFactorVerifier`): a code works once, and
wrong codes count for the lockout of the second factor.

### API keys (automation)

An administrator creates keys for itself with a bearer token. The key is in the answer only, once; the server stores
only its SHA-256 hash.

```bash
curl -s https://sftp.example.com/api/v1/api-keys -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"terraform","expiresAt":"2027-01-01T00:00:00Z","scopes":["ManageUsers"]}'
# {"apiKey":{"id":1,"name":"terraform","prefix":"fss_AbCdEfGh",...},"key":"fss_..."}

curl -s https://sftp.example.com/api/v1/users -H "X-API-Key: fss_..."
```

- A key acts with the current permissions and scope role of its administrator. `scopes` (admin permission names)
  narrow it further; a key cannot have a permission that its administrator does not have.
- A key of a disabled or removed administrator, an expired key and a request from an address that the administrator
  may not log in from (`AllowedIps`) are refused.
- A request with an API key cannot create or revoke API keys, so a leaked key cannot make new ones.
- `GET /api/v1/api-keys` lists the keys of the caller; `?all=true` (ManageAdmins) lists those of the administrators it
  may manage. `DELETE /api/v1/api-keys/{id}` revokes a key.
- The changes of an administrator through the API key are in the audit log as `name (API key terraform)`.

## Resources

| Route | Permission | Operations |
|---|---|---|
| `/users` | ManageUsers (and the scope role) | list (`?search`, `?roleId`), get, create, `PUT`, `PATCH`, delete |
| `/groups` | read: ManageUsers or ManageGroups; change: ManageGroups (and the scope role) | list, get, create, `PUT`, `PATCH`, delete (only without members); `GET /{id}/members` |
| `/groups/{id}/members` | ManageUsers | `POST {username, primary}` adds a user (primary or secondary group), `DELETE /{id}/members/{username}` removes it |
| `/groups/{id}/quotas` | read: ManageUsers or ManageGroups; change: ManageGroups | get, `PUT` (disk, transfer, bandwidth of the members without their own) |
| `/users/{username}/public-keys` | ManageUsers | list, add (authorized_keys text), remove (`?fingerprint=SHA256:...`), `POST .../generate` (returns the private key once) |
| `/users/{username}/quotas` | ManageUsers | get (own settings, and the effective limits with their usage), `PUT` (disk, transfer, bandwidth), `POST .../scan`, `POST .../transfer/reset` |
| `/virtual-folders` | read: ManageUsers or ManageFolders; change: ManageFolders | list, get, create, `PUT`, `PATCH`, delete |
| `/storage-providers` | any administrator | the storage providers and their options; `POST /storage-providers/test` tries a storage |
| `/admins`, `/roles` | ManageAdmins | list, get, create, `PUT`, `PATCH` (admins), delete |
| `/api-keys` | any administrator (bearer token) | list, create, revoke |
| `/connections` | ViewConnections; DisconnectConnections to close one | list, `DELETE /connections/{id}` |
| `/audit` | ViewAudit | the audit log, newest first: `?username`, `?type`, `?status`, `?from`, `?to` |
| `/shares` | ManageUsers (and the scope role) | the share links of the users (#70), newest first (`?username`), without the password hash; `DELETE /shares/{id}` revokes one |
| `/webhooks` | ManageEvents | list, get, create, `PUT`, `PATCH`, delete, `POST /{id}/test`, `GET /{id}/deliveries`, `POST /deliveries/{id}/redeliver`, `GET /event-types` |
| `/event-rules` | ManageEvents | list, get, create, `PUT`, `PATCH`, delete, `POST /{id}/run` (scheduled and on-demand rules), `GET /{id}/runs`, `GET /action-types` |
| `/ip-bans` | ManageSettings | the active auto-bans, `DELETE /ip-bans/{address}` |
| `/settings` | read: any administrator; change: ManageSettings | get (with the host key fingerprints), `PUT`/`PATCH` (a value that is not given stays) |
| `/status` | any administrator | version, start time, uptime, node, and the permissions of the caller |
| `/dump`, `/load` | SuperAdmin | export and import of every stored object (below) |

The users create their share links (#70) in the web client; the API lists and revokes them. The second-factor
administration (#63: set up or reset the TOTP app of a user or an administrator) has no routes yet.

A user has its own settings and the settings of its groups (#61): `primaryGroupId`, `secondaryGroupIds`; a value that
the user does not set (`permissions` and `pathFilters` not given, no `storage`) comes from the groups. The lifecycle
fields are `status` (`Enabled`, `Disabled`), `expiresAt` (UTC), `maxSessions` (0: no limit) and `description`; the views
also have `lastLoginAt` and `passwordChangedAt`. The quotas (#62) are `diskQuota` (`maxSizeBytes`, `maxFiles`),
`transferQuota` (`maxUploadBytes`, `maxDownloadBytes`, `maxTotalBytes`) and `bandwidth` (`uploadKiBPerSecond`,
`downloadKiBPerSecond`, `overrides` by client network), on users, groups and (disk) on each mount; 0 is unlimited. All times are UTC; a time without an offset is UTC.

### Conventions

- **JSON** with camelCase names; enums are strings, and flag sets are arrays of names (`["ManageUsers","ViewAudit"]`,
  `{"/": ["List","Download"]}`). Login methods have their SSH names: `password`, `publickey`, `keyboard-interactive`.
- **Lists** have paging: `?offset=0&limit=100` (at most 1000), and the answer is `{items, total, offset, limit}`.
- **`PUT`** saves the whole object: a value that is not given gets its default. **`PATCH`** is a JSON merge patch
  (RFC 7396, `application/merge-patch+json`): it changes only the given members (`null` removes one), for example
  `{"onlyWhitelistedIps": true}`.
- **Secrets are write-only.** A user password, an administrator password, the storage secrets (`[Secret]` options,
  such as the S3 secret key) and the webhook secret are never returned; the answer says only whether they are set
  (`hasPassword`, `storage.storedSecrets`, `hasSecret`). A save without the secret keeps the stored one; remove a
  storage secret with `storage.clearSecrets`, a password with `removePassword`.
- **Errors** are RFC 9457 problem details (`application/problem+json`): 400 with the problems by field for invalid
  input, 401 without a valid login, 403 without the permission, 404 for an object that does not exist or is not in
  the scope of the caller, 409 for a name that is used, 429 for too many requests.

A storage of a user or a virtual folder:

```json
{
  "provider": "s3",
  "options": { "Bucket": "files", "Region": "eu-north-1", "AccessKey": "AKIA...", "SecretKey": "..." },
  "clearSecrets": []
}
```

The option names and kinds are in `GET /api/v1/storage-providers`. No storage (or an empty provider) is the default
storage: the local disk at `rootDirectory`.

```bash
curl -s https://sftp.example.com/api/v1/users -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{
  "username": "alice",
  "rootDirectory": "/srv/sftp/alice",
  "password": "a long password",
  "permissions": { "/": ["List", "Download"], "/incoming": ["All"] }
}'

curl -s -X PATCH https://sftp.example.com/api/v1/users/alice -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/merge-patch+json' -d '{"whitelistedIps": ["10.0.0.0/8"], "onlyWhitelistedIps": true}'
```

## Dump and load

`GET /api/v1/dump` exports the roles, administrators, virtual folders, groups, users, webhooks, event rules and settings as one JSON
document, independent of the settings database. Objects refer to each other by name, so the dump can be loaded into
another server. Passwords and keys are in it as their hashes and public keys. The storage (also of groups) and webhook secrets are in
it only when the request has a passphrase (at least 12 characters) in the header `X-Dump-Passphrase`: they are then
encrypted with it (AES-256-GCM, key from PBKDF2-SHA256). Without the header the secrets are left out and listed in
`omittedSecrets`. Keep a dump safe: it has the password hashes.

```bash
curl -s https://old.example.com/api/v1/dump -H "Authorization: Bearer $TOKEN" \
  -H 'X-Dump-Passphrase: a long passphrase' > dump.json

curl -s 'https://new.example.com/api/v1/load?mode=add' -H "Authorization: Bearer $TOKEN2" \
  -H 'X-Dump-Passphrase: a long passphrase' -H 'Content-Type: application/json' --data-binary @dump.json
# {"mode":"Add","added":12,"updated":0,"skipped":1,"errors":[]}
```

`POST /api/v1/load?mode=` takes `add` (default: an object that exists is an error and stays as it is), `update`
(replace the existing objects and save the settings) or `skip` (leave them). The secrets are encrypted again with the
data protection keys of the new server. The administrator who loads is never replaced by the dump. Each object that
cannot be loaded is in `errors`; the others are loaded.

## Change the API

The routes are in `SshServer.Api/Endpoints`. After a change of a route or a model, write the new OpenAPI document and
commit it:

```bash
FREESFTPSHARP_UPDATE_OPENAPI=1 dotnet test tests/FreeSftpSharp.Tests --filter OpenApiDocumentTests
```
