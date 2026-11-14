# Event rules

An event rule automates the server without code (#68): "when a file lands in `/incoming`, move it to `/processed`
and send an email", "every night remove the files older than 30 days in `/tmp`". Add rules on the admin page
**Event rules** (`/eventrules`, permission `ManageEvents`). Nothing runs until a rule exists, and with no rule an event
costs no database read.

The rules are in the settings database (tables `EventRules` and `EventRuleRuns`), so they need the SQLite settings
provider; with `Settings:Provider=LiteDb` the page says that they are off.

## Trigger

| Trigger | When the rule runs |
| --- | --- |
| On events | After one of the selected events, in the background, for example `File.Upload`, `File.Delete`, `Auth.LoginFailed`, `Auth.IpBanned`, `Provider.Add`. A rule on `File.PreUpload`, `File.PreDownload` or `File.PreDelete` runs **before** the operation: the client waits, and when an action fails (or the rule does not end within `EventRules:SyncTimeoutSeconds`) the operation is refused with "permission denied". Such a rule cannot have other events. |
| On a schedule | A cron expression with five fields (minute hour day month weekday, for example `0 3 * * *`) or a macro such as `@hourly`, in a time zone (an IANA id such as `Europe/Stockholm`; empty is UTC). After a stop of the server, the missed occurrences give one run, not one each. |
| On demand | Only the **Run now** button. Scheduled rules have it too. |

With several nodes on one database (#75), a node runs an occurrence of a schedule only when it claims it with one
conditional update of the rule row, so the rule runs once per occurrence.

## Conditions

All conditions must match; an empty one matches everything.

- **Users**: user names, without case; `*` is any text and `?` one character, for example `partner-*`. A scheduled or
  on-demand rule with a file action runs its actions once for **each** user that matches (no condition: every user).
- **Path**: a glob over the virtual path (or the target path of a rename), as for webhooks: `*` within a directory,
  `**` over directories, for example `/incoming/*`. Set, it skips the events that are not file events.
- **Protocols** (for example `SFTP`), **smallest and largest file size** in bytes, **file results** (`Ok`, `Error`,
  `QuotaExceeded`, `Denied`) and the **object types** of provider events (for example `User`, `Webhook`).

## Actions

The actions run in their order. An action can **stop on failure** (the next actions do not run). A **failure action**
runs only when another action of the run failed, for example an email to the operator. Each run is kept in the
execution history (the newest `EventRules:RunHistoryPerRule`, default 100, per rule) with its status, duration and one
line per action.

| Action | What it does |
| --- | --- |
| Move or rename | Moves a file or directory of the user (default source `{{VirtualPath}}`) to the target; creates the parent of the target. A storage without rename copies and deletes a file. |
| Copy | Copies a file or a directory tree of the user on the server. |
| Delete | Removes files, or empty directories (or with their content when set). The user root is never removed. |
| Create directories | Creates directories with their missing parents. |
| Check that files exist | Fails when a path does not exist; with "stop on failure" the next actions run only when the files are there. |
| Compress to zip | Writes files and directories of the user into a zip archive in the storage of the user. The archive is built in a temporary file of the server (removed at the end), so with encrypted storage the files are briefly on the local disk unencrypted. |
| Data retention | Removes the files older than a number of days in folders of the user (and below), optionally the directories that are empty then. The next actions get `{{RetentionDeleted}}` (the count) and `{{RetentionReport}}`. |
| Email | Sends an email with placeholders in the subject and the text; it can attach the file of the event (at most `EventRules:Smtp:MaxAttachmentBytes`). Without a mail server it is skipped, not failed. |
| Command | Starts an executable of the operator. Off unless the operator allows it (see below). |
| Webhook | Puts the event in the outbox of a webhook of the Webhooks page (signature, retries and delivery history as in [WEBHOOKS.md](WEBHOOKS.md)), with the field `rule`. A scheduled run sends a `System.ScheduledJobRan` event. Set **Only for event rules** on a webhook that should get only these events. |
| Rescan quota | Queues a scan of the disk usage of the user (its storage and the folders with a disk quota), see the quotas in [ARCHITECTURE.md](ARCHITECTURE.md#quotas-and-bandwidth). |
| Reset transfer quota | Sets the uploaded and downloaded bytes of the user to 0, for example on a monthly schedule. |

The file actions work on the storage of the user (`IFileSystemFactory`), so they work for every storage backend. They
are server operations: the per-path permissions and path filters of the user are not applied (the user root still
is), so a rule can move a file to a directory that the user cannot write. Their operations are in the audit log with
the protocol `EventRules`, and they never start a rule, so a rule cannot trigger itself.

Not done yet: quota actions (need #62), group conditions and user checks such as inactivity or expiration (need #61),
role conditions, and a backup action (needs the export format of #67).

## Placeholders

The text options of the actions can have placeholders: `{{Name}}`, or `{{Name | urlencode}}` with a filter
(`urlencode`, `lower`, `upper`). An unknown name gives an empty text.

| Placeholder | Value |
| --- | --- |
| `{{Rule}}` | the name of the rule |
| `{{Event}}` | the event, for example `File.Upload`; `Schedule` or `OnDemand` |
| `{{Username}}` | the user |
| `{{VirtualPath}}`, `{{VirtualTargetPath}}` | the path of the file, and the new path of a rename or copy |
| `{{Name}}`, `{{Dir}}` | the file name, and its directory |
| `{{FileSize}}`, `{{Status}}`, `{{Protocol}}`, `{{Ip}}`, `{{Message}}` | from the event |
| `{{Timestamp}}`, `{{Date}}` | the time of the event (ISO 8601 UTC), and the date of the run (`yyyy-MM-dd`) |
| `{{ObjectType}}`, `{{ObjectName}}`, `{{ObjectData}}` | the object of a provider event; the data is JSON without secrets |
| `{{RetentionDeleted}}`, `{{RetentionReport}}` | after a data retention action |

## Commands

The Command action is off by default. The operator turns it on and lists the executables it may start:

```json
"EventRules": {
  "AllowCommands": true,
  "AllowedCommands": [ "/opt/erp/import-file" ],
  "CommandTimeoutSeconds": 30
}
```

A rule with a Command action cannot be saved while commands are off or the executable (an absolute path) is not in
the list, and a stored one is refused when it runs after the operator changed the configuration. The process gets
each argument line as one value (`ProcessStartInfo.ArgumentList`): no shell parses it, so a file name such as
`a; rm -rf ~` is only a file name. The environment of the server is not passed on: the process gets only the
`NAME=value` lines of the action (add `PATH` when it needs one). Its working directory is the temporary directory; after
`CommandTimeoutSeconds` the process tree is killed and the action fails. Exit code 0 is success; the first 2 KiB of the
output are in the history.

## Email

```json
"EventRules": {
  "Smtp": {
    "Host": "smtp.example.com",
    "Port": 587,
    "Security": "Auto",
    "Username": "sftp@example.com",
    "Password": "use an environment variable or a secret store",
    "From": "sftp@example.com",
    "MaxAttachmentBytes": 10485760
  }
}
```

`Security` is `Auto` (STARTTLS when offered, implicit TLS on port 465), `StartTls`, `SslOnConnect` or `None`. Without
`Host`, Email actions are skipped and the page says so. Put the password in an environment variable
(`EventRules__Smtp__Password`), not in a file under version control.

## Options

| Setting | Default | Effect |
| --- | --- | --- |
| `EventRules:AllowCommands` | false | Allows the Command action. |
| `EventRules:AllowedCommands` | empty | The absolute paths of the executables a Command action may start. |
| `EventRules:CommandTimeoutSeconds` | 30 | The longest time of a command (1 to 3600). |
| `EventRules:MaxConcurrentRuns` | 4 | How many rule runs of events a node does at the same time (1 to 64). |
| `EventRules:RunHistoryPerRule` | 100 | How many runs of each rule the history keeps. |
| `EventRules:SyncTimeoutSeconds` | 30 | The longest wait of an operation for its `Pre*` rules (1 to 300); then it is refused. |
| `EventRules:Smtp:*` | empty | The mail server, see above. |

## For developers

The engine is the plug-in `SshServer.EventRules` (`AddEventRules(configuration)`). An action type is a singleton
`IEventRuleAction` (`SshServer.Interfaces.EventRules`): a type name, the fields of its options (the admin UI shows
them), a validation and `ExecuteAsync`. The engine finds actions by type and never knows the class; the Webhook action
is registered by `AddWebhooks`. The `EventRuleSink` (an event sink) and the `EventRuleHook` (the `Pre*` hook) put the
runs in a queue, and the `EventRuleWorker` runs them, so the event bus does not depend on the storage. The
`EventRuleScheduler` uses the `TimeProvider`, so tests use a fake clock.
