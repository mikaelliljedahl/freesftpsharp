# Webhooks

A webhook is an HTTP endpoint that gets the events of the server (#66): file transfers and changes, logins and bans,
changes of users and settings. Add webhooks on the admin page **Webhooks** (`/webhooks`). Nothing is sent until a
webhook exists, and with no webhook an event costs no database read and no request.

## Two kinds

| | Asynchronous (default) | Synchronous |
| --- | --- | --- |
| Events | any; no selection means every event except the `Pre*` events | only `File.PreUpload`, `File.PreDownload`, `File.PreDelete` |
| When | after the event, in the background; a slow or dead receiver never delays a transfer | before the operation; the client waits for the answer |
| Answer | `2xx` is delivered; anything else is sent again later | `2xx` allows the operation; `403` refuses it; anything else, or no answer within the timeout, refuses it (fail closed) unless **fail open** is set |
| Retries | 10 s, 1 min, 5 min, 30 min, 2 h (plus up to 20 % jitter), then a dead letter | none; the answer is kept in the deliveries list |

A refused operation gives the client "permission denied" (SFTP `SSH_FX_PERMISSION_DENIED`). For a `403`, the server
adds the `message` field of a JSON answer (or the text of a plain answer), at most 200 characters, for example
`Permission denied: /in/a.csv: virus found`. Clients that show the status text of the server (for example SSH.NET) show it; OpenSSH `sftp` shows only
"Permission denied".

Asynchronous deliveries are rows of an outbox in the settings database (`WebhookDeliveries`): they survive a
restart, and each one is delivered at least once. A receiver should use the `X-FreeSftpSharp-Delivery` header (the
same for every attempt) to ignore a repeat. The deliveries page shows each delivery with its status, attempts and the
start of the last answer (at most 4 KiB); **Redeliver** sends one again. **Send test event** sends a
`System.WebhookTest` event to one webhook.

## Webhooks for event rules

The **Webhook** action of an event rule ([EVENT-RULES.md](EVENT-RULES.md)) puts the event of the rule in the outbox of
a webhook, with the field `rule` (the name of the rule) in the payload; the filters of the webhook are not used. A
webhook with **Only for event rules** gets only these events and none of its own; it cannot be synchronous.

## Filters

- **Events**: "Category.Type", for example `File.Upload`, `File.FirstUpload`, `Auth.LoginFailed`, `Provider.Update`.
- **Users**: only the events of these users (without case). Set, it skips the events without a user.
- **Path**: a glob over the virtual path (or the target path of a rename): `*` within a directory, `**` over
  directories, `?` one character, for example `/incoming/**/*.csv`. Set, it skips the events that are not file events.

## Request

```
POST /your/path HTTP/1.1
Content-Type: application/json; charset=utf-8
User-Agent: FreeSftpSharp-Webhooks
X-FreeSftpSharp-Event: File.Upload
X-FreeSftpSharp-Delivery: 3f0c2a8e-9a51-4c0e-8d3b-0d8f6b1c9a77
X-FreeSftpSharp-Signature: t=1794657600,v1=5d41402abc4b2a76b9719d911017c592...
```

The method is `POST` (or `PUT`), plus the static headers of the webhook. The body is one event:

```json
{
  "event_id": "b8f1d0a2-6c3e-4a57-9f1e-2d7c4b0e5a61",
  "attempt": 1,
  "event": "File.Upload",
  "category": "file",
  "action": "upload",
  "timestamp": 1794657600123456700,
  "time": "2026-11-14T10:00:00.1234567Z",
  "username": "alice",
  "path": "/in/a.csv",
  "virtual_path": "/in/a.csv",
  "file_size": 2048,
  "elapsed": 35,
  "status": 1,
  "status_text": "Ok",
  "protocol": "SFTP",
  "ip": "192.0.2.10",
  "session_id": "0c6b5f1e-…",
  "storage_provider": "local"
}
```

The field names follow the hook payload of SFTPGo where they overlap, with the same values, so a receiver for SFTPGo
can be reused: `action` is `upload`, `first-upload`, `pre-upload`, `download`, `pre-download`, `delete`,
`pre-delete`, `rename`, `mkdir`, `rmdir`, `copy`, `ssh_cmd` (and `login-ok`, `login-failed`, `logout`, `ip-banned`,
`add`, `update`, `delete`, ... for the other categories); `status` is `1` ok, `2` error, `3` quota exceeded, and `4`
refused by a hook; `timestamp` is in nanoseconds since 1970; `elapsed` is in milliseconds. `path` is the virtual path
too: the payload never has a physical path. Other fields by category:

- file: `target_path` and `virtual_target_path` (rename, copy), `message` (why it failed), `open_flags_text`, `metadata`.
- auth: `username`, `ip`, `protocol`, `login_method`, `reason`, `session_id`.
- provider: `object_type` (`user`, `webhook`, ...), `object_name`, `actor`, `changed_fields`, `object` (the object
  without secrets: a user has `has_password`, never the hash or the key).
- system: `source`, `message`.

No payload has a password, a key, a secret or a token.

## Verify the signature

`X-FreeSftpSharp-Signature` is `t=<unix seconds>,v1=<hex>`. The hex is the lower-case HMAC-SHA256 of the text
`t + "." + body` with the secret of the webhook as the key (both UTF-8), over the exact bytes of the body. A webhook
without a secret sends no signature. To check a request:

1. Read the raw body before you parse it.
2. Compute the HMAC of `t + "." + body` and compare it with `v1` in constant time.
3. Refuse a `t` that is more than a few minutes old (replay).

C#:

```csharp
static bool Verify(string secret, string header, string body, TimeSpan tolerance)
{
    var parts = header.Split(',').Select(p => p.Split('=', 2)).Where(p => p.Length == 2).ToDictionary(p => p[0], p => p[1]);
    if (!parts.TryGetValue("t", out var t) || !parts.TryGetValue("v1", out var v1) || !long.TryParse(t, out var seconds))
        return false;
    if (Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - seconds) > tolerance.TotalSeconds)
        return false;
    var expected = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(t + "." + body));
    return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Convert.ToHexStringLower(expected)), Encoding.ASCII.GetBytes(v1));
}
```

Python:

```python
import hashlib, hmac, time

def verify(secret: str, header: str, body: bytes, tolerance: int = 300) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(",") if "=" in p)
    t, v1 = parts.get("t"), parts.get("v1")
    if not t or not v1 or abs(time.time() - int(t)) > tolerance:
        return False
    expected = hmac.new(secret.encode(), t.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1)
```

## Security

- The URL must be `https://`. `http://` is allowed only to `localhost`, a loopback address or a private address
  (10/8, 172.16/12, 192.168/16, fc00::/7), and only with `Webhooks:AllowInsecureWebhooks=true`. A URL cannot have a
  user name or password; put a credential in a static header.
- The server never follows a redirect: a `3xx` answer is a failure.
- The secret is stored encrypted with ASP.NET Core data protection. The keys are in the directory
  `DataProtection:KeysPath` (default `keys` next to the app; on Windows they are encrypted with DPAPI). Both hosts use
  it. Without the keys a stored secret cannot be read: the webhook then fails until you set a new secret. The secret
  is shown once, when you create or generate it.
- At most 4 KiB of an answer is read, kept and logged.

## Options

| Key | Default | Meaning |
| --- | --- | --- |
| `Webhooks:AllowInsecureWebhooks` | `false` | allow `http://` to loopback and private addresses |
| `Webhooks:DeliveryRetentionDays` | `30` | remove finished deliveries older than this; `0` keeps all |
| `Webhooks:MaxConcurrentDeliveries` | `4` | asynchronous requests in flight on one node |

Each webhook has a timeout of 1 to 30 seconds (default 10). With `Settings:Provider=LiteDb` there are no webhooks.

## Several nodes

The dispatcher of each node takes due deliveries with a lease (two minutes): another node does not take a delivery
while its lease runs, and the deliveries of a node that stopped are taken by another node when their leases end.
Each node reloads the webhooks every 30 seconds, so a change on one node reaches the others within that time.
