# OpenID Connect sign-in

The admin UI and the web client (#69) can sign in through the identity provider of an organisation with OpenID
Connect (issue #73): Keycloak, Microsoft Entra ID, Okta, Google Workspace, Authelia and other providers with a
discovery document. The administrators and the users need no separate password, and an account that the provider
disables or removes cannot sign in any more. SAML is not supported.

It is **off by default**. Without an `Auth:Oidc` section no handler is registered, the login pages look as before and
the callback paths are not handled. The two areas have their own configuration, client and callback path, and they
can be turned on separately:

| Area | Section | Callback (redirect URI) | After the logout at the provider | Back-channel logout |
| --- | --- | --- | --- | --- |
| Admin UI | `Auth:Oidc:Admin` | `https://<server>/signin-oidc-admin` | `https://<server>/signout-callback-oidc-admin` | `https://<server>/signout-oidc-admin-backchannel` |
| Web client | `Auth:Oidc:Client` (needs `WebClient:Enabled`) | `https://<server>/signin-oidc-client` | `https://<server>/signout-callback-oidc-client` | `https://<server>/signout-oidc-client-backchannel` |

## How it works

- **Authorization code flow with PKCE** (S256) and `response_mode=form_post`. The ASP.NET Core handler checks the
  state, the nonce, the issuer, the audience and the signature of the id_token. If the discovery document lists a
  pushed authorization request endpoint (PAR, for example Keycloak), the handler uses it.
- **No tokens are kept.** The handler signs in to the local login cookie of the area with the local claims only (the
  same cookie as a password login): no id_token, access token or refresh token is stored. The session is then checked
  like a password session (against the stored account on each request).
- **Separate areas.** The admin sign-in uses the admin cookie, the client sign-in the cookie of the web client (path
  `/client`). An admin sign-in does not open `/client`, and a client sign-in does not open the admin UI, also when one
  account of the provider has both roles.
- **The user name.** The claim `UsernameClaim` (default `preferred_username`) is the name of the local account
  (`Admin.Username` or `User.Username`). Use a claim that the user cannot change at the provider.
- **The required role.** With `RequiredRoleValue`, the claim `RoleClaim` must have that value, otherwise the sign-in is
  refused with a clear page ("Your account at ... does not have the role that is needed here"). `RoleClaim` can be a
  path into a JSON claim, for example `realm_access.roles` of Keycloak.
- **The local rules still apply.** A disabled or expired account, an address outside the allowed networks, the global
  IP rules and the auto-ban refuse the sign-in. A web client user needs the protocol "Web client".
- **No local second factor.** After a sign-in with the provider, the local TOTP step (#63) is skipped, also for an
  account that has an authenticator app on this server: the provider is expected to enforce the multi-factor
  authentication. Turn it on there (for example a Keycloak OTP or WebAuthn policy, or Entra ID Conditional Access).
- **Events.** A sign-in gives the auth events `LoginOk` (method `oidc`) and `IdpLogin`, a refusal `LoginFailed` with
  the reason. An event rule (#68) on `Auth.IdpLogin` can adjust the account after the sign-in.
- **Logout.** The logout ends the local session. After a sign-in with the provider, it also ends the session at the
  provider when the provider publishes an `end_session_endpoint` (RP-initiated logout with `client_id` and
  `post_logout_redirect_uri`; there is no id_token to send as a hint).
- **Logout at the provider** (back-channel, #145). When the session ends at the provider (the user logs out there, an
  administrator of the provider ends it, or it expires), a provider with OpenID Connect Back-Channel Logout 1.0 posts a
  `logout_token` to the back-channel URL of the area. The server checks the token: signed with a key of the discovery
  document (not `alg: none`), the issuer, the client id as audience, `iat`, the expiry when it has one, the
  back-channel logout event in `events`, a `sid` or a `sub`, and no `nonce`. It then ends the local sessions of that
  provider session: the same `sid` (the id_token of the sign-in must have one; Keycloak sends it), or every session of
  the `sub` when the token has no `sid`. It answers 200 (also when no session matched) or 400 `invalid_request`. A
  password login is never ended by the provider.
  - **Web client:** the browser session is removed from the session store (as "Disconnect" in the admin UI): the next
    request of the browser goes to the login page, and the logout is an auth event.
  - **Admin UI:** the admin login cookie has no session on the server. The cookie of a sign-in keeps the `sid`, the
    `sub` and the time of the sign-in, and the server keeps each logout for 12 hours in memory (longer than an admin
    cookie lives without a request); the cookie check of each request and the check of a Blazor circuit (every 30
    seconds) reject a cookie of an ended session. **Limits:** the logouts are per node and in memory: with several
    nodes only the node that got the logout ends the sessions (the provider calls one URL), and a restart forgets
    them, so a cookie from before the restart works again until it expires (8 hours without a request). Where that
    matters, also disable the administrator, which ends its sessions on every node.
  - The `jti` of a token is not stored (a replayed logout only ends the same sessions again).
- **SameSite cookies.** The provider posts the code from its own site, so the browser does not send the
  SameSite=Strict login cookie on the redirect that follows. The callback therefore ends on a small page
  (`/signin-done`, `/client/signin-done`) that continues with a same-site navigation.

### Administrators

The administrator with the name of the user name claim must exist (create it on the Admins page or with
`--create-admin`). A local administrator can then use both its password and the provider.

With `AutoProvision`, an administrator that does not exist is created at its first sign-in. It gets the union of the
permissions of its role values in `RolePermissions`, and a scope role (#60) when one of its role values is the name of
a scope role. A sign-in without a mapped role value is refused.

The new administrator belongs to the provider `oidc` (#145, `Admin.AuthenticationProvider`, a badge on the Admins page
and `authenticationProvider` in the REST API and the dump). It has no local password: the password form cannot log it
in, and the Admins page (disabled fields with a hint), the REST API and the own password change refuse to set one ("The
password of this account is managed by oidc"). A local administrator (created on the Admins page or with
`--create-admin`) stays local: it can use both its password and the provider.

By default the permissions are set once, at the creation; change them later on the Admins page. With
`SyncRolesOnSignIn`, the permissions and the scope role of an `oidc` administrator follow its role values at every
sign-in (mapped with `RolePermissions` as at the creation); a sign-in without a mapped role value is then refused and the
administrator is not changed. A local administrator is never changed by the sign-in.
#### The first administrator

The sign-in never opens an installation without administrators by itself: `AutoProvision` creates administrators only
with the permissions of `RolePermissions`, and while no administrator exists the admin UI answers 503 (the SSH server
and the web client still run). There are three ways to the first administrator:

1. **`--create-admin <name>`** on the command line (or `AdminAuth:UserName` and `AdminAuth:PasswordHash`): a local
   super admin with a password. It can then also sign in with the provider, if the provider has the same name.
2. **A role mapped to `SuperAdmin`** with `AutoProvision`, for example `"RolePermissions": { "sftp-admins": "SuperAdmin" }`
   - but only after the first administrator exists, because the admin UI is closed before.
3. **`BootstrapAdmin`** (#145): the user name (the claim `UsernameClaim`) of the first administrator. While no
   administrator is stored, the admin UI stays open for the sign-in, and the first sign-in of exactly this name (with
   `RequiredRoleValue`, when it is set) creates it as a super admin of the provider `oidc`, also without
   `AutoProvision`. The log says so at the start. Once any administrator exists, the setting is not used any more:
   remove it after the first sign-in. Use a name that only the right person has at the provider.

```json
{
  "Auth": {
    "Oidc": {
      "Admin": {
        "Authority": "https://keycloak.example.org/realms/sftp",
        "ClientId": "freesftpsharp-admin",
        "RoleClaim": "realm_access.roles",
        "RequiredRoleValue": "sftp-admin",
        "BootstrapAdmin": "alice"
      }
    }
  }
}
```

With `SyncRolesOnSignIn` the role values rule for the bootstrap admin too: map one of its roles to `SuperAdmin`, or it
loses the permissions at its next sign-in.

### Web client users

A local user (created in the admin UI or with `user add`) with the name of the user name claim signs in as itself; the
sign-in does not change it. A user of another authentication provider (#64, for example `ldap`) is refused.

With `AutoProvision`, a user that does not exist is created at its first sign-in by the same provisioning as the
authentication providers (#64): it belongs to the provider `oidc` (a badge in the admin UI), it has no local password
(the web client, the admin UI and the REST API refuse to set one: "The password of this account is managed by oidc"),
its primary group is `TemplateGroup`, and its secondary groups are the groups of `GroupsClaim`, mapped with `GroupMap`.
Give the storage (for example a storage template `/srv/sftp/%username%`), the virtual folders and the permissions to
the template group (#61). Without a storage from a group, the user gets `<Auth:ExternalUsers:RootDirectory>/<name>`
on the local disk. At every later sign-in its secondary groups follow the groups of the token (a group without a
local group is skipped).

**Other protocols** (#145). The provider `oidc` owns the password only: a user of the sign-in has no password for
SFTP, WebDAV or FTP, but its local credentials work there.

- **SSH public keys** for SFTP: the user adds them on the account page of the web client (`/client/account`), or an
  administrator in the user form or the REST API. They are checked like the keys of a local user (expiry, allowed
  login methods, multi-step logins).
- **App passwords** for WebDAV, FTP and SFTP clients: the user creates them on the account page (name, protocols,
  optional expiry; the secret is shown once), or an administrator in the user form ("App passwords") or the REST API.
  An app password does not open the web client.

A password login of such a user over SFTP, WebDAV or FTP is refused ("the password of the user is managed by oidc").

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `Authority` | empty | The issuer, for example `https://idp.example.org/realms/sftp`. Empty: the area has no sign-in. |
| `ClientId` | - | The client at the provider (required with `Authority`). |
| `ClientSecret` | empty | The secret of a confidential client. Empty: a public client (PKCE protects the code). Put it in an environment variable (`Auth__Oidc__Admin__ClientSecret`) or the user secrets. |
| `Scopes` | `["profile"]` | The scopes besides `openid`, for example `["profile", "email"]`. |
| `UsernameClaim` | `preferred_username` | The claim with the local user name. |
| `RoleClaim` | `roles` | The claim with the roles; a dot is a path into a JSON claim (`realm_access.roles`). |
| `RequiredRoleValue` | empty | A value that `RoleClaim` must have. Empty: every account of the provider (with a local account) may sign in. |
| `AutoProvision` | `false` | Create the account at its first sign-in. |
| `DisplayName` | `single sign-on` | The text of the button: "Sign in with ...". |
| `DisableLocalLogin` | `false` | Remove the password form of the area; `POST /Login` (or `POST /client/login`) answers 404. For the admin UI also `POST /api/v1/token` of the REST API answers 403. Turn it on when the sign-in works. The command line (`--create-admin`) still works. |
| `RequireHttpsMetadata` | `true` | The discovery document over HTTPS only. Turn it off only for a test provider on the same host. |
| `RolePermissions` (admin) | empty | For `AutoProvision`: role value -> comma separated `AdminPermissions`, for example `{ "sftp-admins": "SuperAdmin", "sftp-helpdesk": "ViewConnections, ViewAudit" }`. Required with `AutoProvision` and `SyncRolesOnSignIn`. |
| `BootstrapAdmin` (admin) | empty | While no administrator exists: the user name whose first sign-in creates the first super admin (provider `oidc`). Not used once an administrator exists. |
| `SyncRolesOnSignIn` (admin) | `false` | The permissions and the scope of an `oidc` administrator follow its role values at every sign-in. Off: they are set once, at the creation. |
| `TemplateGroup` (client) | empty | The primary group of a new user. |
| `GroupsClaim` (client) | `groups` | The claim with the groups. Empty: the groups are not mapped. |
| `GroupMap` (client) | empty | Group of the provider -> local group, for example the object ids of Entra ID. Empty: the local group with the same name (a leading `/` of a Keycloak group path is removed). |

The settings are checked at the start: an `Authority` without `ClientId`, an `http://` authority with
`RequireHttpsMetadata`, or an unknown permission name stop the start with a clear message.

`DisableLocalLogin` of the admin UI also turns off the password token endpoint of the REST API (#67): `POST
/api/v1/token` answers 403 with a problem text, also for the right password, and the password is not checked. API keys
(`X-API-Key`) keep working; create them before you turn the password login off, or with a bearer token while it is on.

## Keycloak

The walkthrough uses Keycloak 26 and the server `https://sftp.example.org`.

1. **Realm.** Create a realm, for example `sftp`. The authority is `https://keycloak.example.org/realms/sftp`.
2. **Roles.** *Realm roles* > *Create role*: `sftp-admin` and `sftp-user`. Give them to the users (*Users* > user >
   *Role mapping*).
3. **Admin client.** *Clients* > *Create client*: type OpenID Connect, client ID `freesftpsharp-admin`. *Client
   authentication* on, *Standard flow* on, *Direct access grants* off. *Valid redirect URIs*
   `https://sftp.example.org/signin-oidc-admin`, *Valid post logout redirect URIs*
   `https://sftp.example.org/signout-callback-oidc-admin`. Under *Advanced* > *Advanced settings* set *Proof Key for
   Code Exchange Code Challenge Method* to `S256`. For the back-channel logout set *Backchannel logout URL*
   `https://sftp.example.org/signout-oidc-admin-backchannel` and keep *Backchannel logout session required* on (the
   token then has the `sid`). Copy the secret from the *Credentials* tab.
4. **Client of the web client.** The same with client ID `freesftpsharp-client` and the `-client` paths (also
   `https://sftp.example.org/signout-oidc-client-backchannel`). It can be a public client (*Client authentication* off).
5. **Roles in the id_token.** By default Keycloak puts the realm roles only in the access token. *Client scopes* >
   `roles` > *Mappers* > `realm roles`: turn on *Add to ID token*. Then use `"RoleClaim": "realm_access.roles"`. (Or add
   a mapper *User Realm Role* with the claim name `roles`, multivalued, to the dedicated scope of the client.)
6. **Groups.** For the web client: *Clients* > `freesftpsharp-client` > *Client scopes* > `freesftpsharp-client-dedicated`
   > *Add mapper* > *By configuration* > *Group Membership*: token claim name `groups`, *Full group path* off, *Add to
   ID token* on. Create local groups with the same names (or use `GroupMap`).

```json
{
  "WebClient": { "Enabled": true },
  "Auth": {
    "ExternalUsers": { "RootDirectory": "/srv/sftp/users" },
    "Oidc": {
      "Admin": {
        "Authority": "https://keycloak.example.org/realms/sftp",
        "ClientId": "freesftpsharp-admin",
        "DisplayName": "Keycloak",
        "RoleClaim": "realm_access.roles",
        "RequiredRoleValue": "sftp-admin"
      },
      "Client": {
        "Authority": "https://keycloak.example.org/realms/sftp",
        "ClientId": "freesftpsharp-client",
        "DisplayName": "Keycloak",
        "RoleClaim": "realm_access.roles",
        "RequiredRoleValue": "sftp-user",
        "AutoProvision": true,
        "TemplateGroup": "partners"
      }
    }
  }
}
```

Set the admin secret with `Auth__Oidc__Admin__ClientSecret=<secret>`. The realm of the CI tests is in
[tests/keycloak/freesftpsharp-realm.json](../tests/keycloak/freesftpsharp-realm.json).

## Microsoft Entra ID

1. **App registration.** *Entra ID* > *App registrations* > *New registration*, for example "FreeSftpSharp admin".
   *Supported account types*: this organisational directory only. *Redirect URI*: platform *Web*,
   `https://sftp.example.org/signin-oidc-admin`. Under *Authentication* add
   `https://sftp.example.org/signout-callback-oidc-admin` as a second redirect URI (Entra uses the list for the logout
   too). Do not turn on the implicit grant.
2. **Secret.** *Certificates & secrets* > *New client secret*. Note the expiry: the sign-in fails after it.
3. **App roles.** *App roles* > *Create app role*: allowed member types *Users/Groups*, value `sftp-admin`. Then
   *Enterprise applications* > the app > *Users and groups* > *Add user/group* and give the role. Set *Properties* >
   *Assignment required?* to *Yes*, so only assigned accounts can sign in. The roles come in the claim `roles`.
4. **Groups (web client).** In the registration of the web client: *Token configuration* > *Add groups claim* >
   *Security groups*, ID token: *Group ID*. The claim `groups` has object ids: map them with `GroupMap`. An account in
   more than 200 groups gets no `groups` claim (the overage claim is not read); assign the groups to the app to keep
   the list short.
5. **Authority.** `https://login.microsoftonline.com/<tenant id>/v2.0`.

```json
{
  "Auth": {
    "Oidc": {
      "Admin": {
        "Authority": "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0",
        "ClientId": "<application (client) id>",
        "DisplayName": "Microsoft",
        "Scopes": [ "profile", "email" ],
        "RequiredRoleValue": "sftp-admin"
      },
      "Client": {
        "Authority": "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0",
        "ClientId": "<application (client) id of the web client>",
        "DisplayName": "Microsoft",
        "RequiredRoleValue": "sftp-user",
        "AutoProvision": true,
        "TemplateGroup": "partners",
        "GroupMap": { "11111111-2222-3333-4444-555555555555": "staff" }
      }
    }
  }
}
```

`preferred_username` of Entra ID is the sign-in name (often the UPN, `alice@example.org`); it is a valid local user
name. Entra ID does not guarantee that it never changes: an account with a new UPN is a new local account.
