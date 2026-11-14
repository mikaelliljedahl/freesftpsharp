# FTP and FTPS server

Both hosts (`FxSshSftpServer` and `ServerConsoleApp`) can offer the same users and storage over FTP and FTPS (explicit
TLS, RFC 4217), for the legacy systems that cannot use SFTP (issue #72). FTP is a plug-in (`FreeSftpSharp.Ftp`,
`AddFtp()`) and is **off by default**: without configuration the server opens no FTP port. When it is on, TLS is
**required** by default: a client must send `AUTH TLS` before it logs in, and every data connection is encrypted.
Plain FTP (passwords and files in clear text) only works when the operator turns it on knowingly.

## Turn it on

```json
{
  "Ftp": {
    "Enabled": true,
    "Port": 21,
    "PassivePortRange": "50000-50100",
    "Tls": {
      "CertificatePath": "/etc/freesftpsharp/ftp.pfx",
      "CertificatePassword": "..."
    }
  }
}
```

Every command goes through the user's file system with all its rules: permissions and path filters (#59), virtual
folders (#56), disk and transfer quotas and bandwidth limits (#62, also on the data connections), and the events of the
audit log, webhooks and event rules (#65, protocol `FTP`). The connections are in the connection registry (admin UI page
"Connections", with the open transfers), and an administrator can disconnect them.

| Setting | Default | Effect |
|---|---|---|
| `Ftp:Enabled` | `false` | Turns the FTP server on. |
| `Ftp:Port` | `21` | The port of the control connection. |
| `Ftp:BindAddresses` | all | The local addresses to listen on, for example `["192.0.2.10"]`. Empty: all addresses, IPv4 and IPv6. |
| `Ftp:PassivePortRange` | `50000-50100` | The ports of the passive data connections. The server binds a data listener only to a port of this range. |
| `Ftp:PassiveExternalAddress` | none | The IPv4 address that `PASV` tells the client, for a server behind NAT. `EPSV` needs none. |
| `Ftp:AllowActiveMode` | `false` | Allow `PORT` and `EPRT` (the server connects to the client). |
| `Ftp:Tls:Mode` | `Required` | `Required`, `Optional` (the client chooses) or `Disabled` (plain FTP only). |
| `Ftp:Tls:CertificatePath` | none | A PKCS#12 file (`.pfx`, with `CertificatePassword`) or a PEM certificate (with `CertificateKeyPath`). Empty: the Kestrel certificate (`Kestrel:Certificates:Default`), else a self-signed certificate made at the start (for tests; clients warn about it). |
| `Ftp:Tls:CertificateKeyPath` | none | The PEM private key of a PEM certificate. |
| `Ftp:Tls:CertificatePassword` | none | The password of the PKCS#12 file or of an encrypted PEM key. A secret. |
| `Ftp:Banner` | `FreeSftpSharp FTP server ready.` | The text of the 220 greeting. |
| `Ftp:IdleTimeoutSeconds` | `300` | A control connection without a command is closed after this time (421). |
| `Ftp:DataTimeoutSeconds` | `30` | How long the server waits for a data connection and for data on it. |
| `Ftp:MaxConnectionsPerIp` | `10` | The most control connections from one client address (0: no limit). |
| `Ftp:MaxLoginAttempts` | `3` | Failed logins on one connection before the server closes it. |

Every setting can also come from the environment, for example `Ftp__Enabled=true` and `Ftp__Tls__Mode=Optional`.

## Users

A user logs in with the user name and password, through the same rules as SFTP and WebDAV: the global IP rules and the
auto-ban, the allowed networks of the user and its groups, the status and expiry, the password age and the session limit.
The user needs the protocol FTP (admin UI, user page, "Protocols"; a new user has all protocols). A user with a
multi-step login or a TOTP second factor cannot log in with the password, because FTP cannot ask for a code: create an
**app password** for FTP on the user page and use it as the password.

## TLS modes

- **Required** (default). `USER` and `PASS` before `AUTH TLS` get `530`, and the password is not even checked. `PROT C`
  gets `534` and a transfer without `PROT P` gets `521`, so no file travels in clear text either.
- **Optional.** Plain FTP and FTPS are both accepted. Use it only in a closed network.
- **Disabled.** Plain FTP only (`AUTH TLS` gets `502`). The server logs a warning at the start.

Implicit TLS (port 990) is not supported; every client listed below can use explicit TLS. The control and data
connections use one TLS context, so a client can resume the TLS session on the data connections.

## Firewall and NAT

FTP needs the control port **and** the passive port range:

- Open `Ftp:Port` (21) and `Ftp:PassivePortRange` (default 50000-50100) for TCP in the firewall. One passive port is in
  use per running transfer; make the range as large as the transfers that run at the same time.
- Behind NAT, set `Ftp:PassiveExternalAddress` to the public IPv4 address and forward the port range to the server.
  Clients that use `EPSV` (most modern clients) do not need it.
- With TLS the firewall cannot read the `PASV` reply, so an FTP helper (`nf_conntrack_ftp`, "FTP inspection") cannot
  open the data ports for you: open the range itself.
- In Docker, publish both, for example `-p 21:21 -p 50000-50100:50000-50100`.

A data connection is accepted only from the address of the control connection (no stolen passive port), and active
mode connects only to the client itself and to a port of 1024 or higher (no FTP bounce, RFC 2577).

## Clients

The examples use `ftp.example.com`, the user `alice` and the default (TLS required). For a self-signed certificate,
the client must accept it (the options to skip the check are only for tests).

**FileZilla.** Site Manager, Protocol "FTP - File Transfer Protocol", Encryption "Require explicit FTP over TLS",
Logon Type "Normal", the user name and password. Transfer mode "Default" (passive). Accept the certificate at the first
connection.

**WinSCP.** New Site, File protocol "FTP", Encryption "TLS/SSL Explicit encryption", host name, port 21, user name
and password. Passive mode is the default (Advanced, Connection).

**lftp.**

```bash
lftp -u alice -e "set ftp:ssl-force true; set ftp:ssl-protect-data true" ftp.example.com
lftp alice@ftp.example.com:/> put report.csv         # upload
lftp alice@ftp.example.com:/> get -c big.iso         # download, resume a partial file
lftp alice@ftp.example.com:/> put -c big.iso         # upload, resume
lftp alice@ftp.example.com:/> mv report.csv old.csv  # rename
lftp alice@ftp.example.com:/> rm old.csv             # delete
```

For a self-signed certificate add `set ssl:verify-certificate no`.

**curl.**

```bash
curl --ssl-reqd --user alice ftp://ftp.example.com/                     # list
curl --ssl-reqd --user alice -T report.csv ftp://ftp.example.com/in/   # upload
curl --ssl-reqd --user alice -o report.csv ftp://ftp.example.com/in/report.csv   # download
curl --ssl-reqd --user alice -C - -T big.iso ftp://ftp.example.com/big.iso       # resume an upload
curl --ssl-reqd --user alice -C - -o big.iso ftp://ftp.example.com/big.iso       # resume a download
curl --ssl-reqd --user alice -Q "RNFR /in/report.csv" -Q "RNTO /in/old.csv" -Q "DELE /in/old.csv" ftp://ftp.example.com/
```

`--ssl-reqd` (also `--ftp-ssl-reqd`) makes curl stop when the server has no TLS; add `-k` for a self-signed certificate.

## Commands

RFC 959 with the extensions that clients use: `USER`, `PASS`, `AUTH TLS`, `PBSZ`, `PROT` (RFC 4217), `FEAT`, `OPTS UTF8
ON` (names are always UTF-8), `SYST`, `NOOP`, `QUIT`, `HELP`, `CLNT`, `TYPE` (A and I; files are sent as stored, without
line end conversion), `MODE S`, `STRU F`, `PWD`, `CWD`, `CDUP`, `MKD`, `RMD`, `DELE`, `RNFR`/`RNTO`, `SIZE`, `MDTM`,
`REST` (resume of `RETR` and `STOR`), `ALLO`, `ABOR`, `STAT`, `PASV`, `EPSV` (RFC 2428, also `EPSV ALL`), `PORT` and
`EPRT` (only with `Ftp:AllowActiveMode`), `LIST`, `NLST`, `MLSD`, `MLST` (RFC 3659, facts `type`, `size`, `modify`),
`RETR`, `STOR`, `APPE` and `SITE CHMOD` (when the storage can set permissions).

The errors of the storage get these replies: `550` (no such file, permission denied, exists, not empty), `552` (quota
exceeded), `553` (name not allowed), `504` (not supported by the storage, for example `APPE` or a resumed upload on a
storage without random writes) and `451` (other failures). A command line is at most 4096 bytes; a longer one closes
the connection.

Not supported: implicit TLS, `SITE` commands other than `CHMOD`, `MFMT`, `STOU`, `REIN`, `CCC`, and an `ABOR` during a
transfer (the client closes the data connection instead, and gets `426`).

## Why not FubarDev.FtpServer

The issue asked to evaluate [FubarDev.FtpServer](https://github.com/FubarDevelopment/FtpServer) first. It is MIT
licensed, but its last release (3.1.2) is from October 2021 and targets .NET Standard and .NET Core 3; it pulls old
packages (Scrutor 2, System.IO.Pipelines 4.5, the .NET Standard 1.x graph), has its own authentication ("membership")
and file system abstraction around streams and paths, and its own DI conventions. Mapping its login to the
`PasswordLoginService`, its connections to the connection registry, and its data connections to the passive port and
address rules would have needed as much code as the commands themselves, with less control over the security rules.
The server therefore implements the commands in-house, over `IFileSystem` only.
