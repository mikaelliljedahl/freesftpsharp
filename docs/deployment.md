# Deployment

Three ways to run the server: the container image, a release archive with systemd, or a Kubernetes StatefulSet.
All of them run the web host (`FxSshSftpServer`: the SFTP server and the admin UI). The server still starts with
no configuration as a local test server; everything below is optional.

Examples are in [`deploy/`](../deploy). Not covered yet: a multi-node setup with PostgreSQL and HAProxy (needs #75),
the MinIO example (the S3 backend is not selectable per user until #56), the FTP ports (21 and the passive range,
with the FTP server) and a Helm chart (a follow-up once the image is stable).

## Container image

```sh
docker run -p 2222:22 -p 8080:80 -v freesftpsharp-data:/data ghcr.io/mikaelliljedahl/freesftpsharp
```

The log of the first start prints a generated admin password once (user `admin`). Open `http://localhost:8080`, log
in and add an SFTP user, then `sftp -P 2222 alice@localhost`. Tags: `latest`, `X.Y.Z`, `X.Y` and `sha-<commit>`
(`linux/amd64` and `linux/arm64`).

| Path or port | Use |
| --- | --- |
| `/data` (volume) | The settings database `freesftpsharp.db` (users, settings, **SSH host keys**), the admin data protection keys (`keys/`), the logs (`logs/`), the generated admin hash and the default user roots (`files/`). Back it up. |
| `/config` | Optional. Mount an `appsettings.Production.json` here (it is read by the web host). |
| 22 | SFTP. |
| 80 | The admin UI and `/healthz`, `/readyz`. Plain HTTP, see "HTTPS" below. |

The image runs as the non-root user `app` (UID 1654) and has a `HEALTHCHECK` on `/healthz`. Container runtimes allow
a non-root user to bind ports 22 and 80. If yours does not, set `SshServer__Port=2222` and
`Kestrel__Endpoints__Http__Url=http://0.0.0.0:8080` (and `HEALTHCHECK_PORT=8080`).

### First run

- **Admin password.** The admin UI is closed without a credential, so the entry point makes one. With
  `FREESFTPSHARP_ADMIN_PASSWORD` set, that password is used (hashed at each start). With `AdminAuth__PasswordHash`
  set, that hash is used. With neither, a password is generated at the first start, printed once to the log, and
  its hash is kept in `/data/admin-password.hash`. Delete that file (and restart) to get a new one.
- **First SFTP user.** Set `FREESFTPSHARP_USER` and `FREESFTPSHARP_USER_PASSWORD` to create a user at start (if it
  does not exist; its root is `/data/files/<name>`). Or use the command line in the running container:

  ```sh
  echo "a-password" | docker exec -i <container> freesftpsharp-user add alice --root /data/files/alice --password-stdin
  docker exec <container> freesftpsharp-user list
  ```

- **Host keys** are generated at the first start into the settings database in `/data`. Keep the volume, or clients
  see a changed host key.
- **Configuration.** Every setting is an environment variable (`Section__Key`): `SshServer__Port`,
  `Observability__Prometheus__Enabled`, `Serilog__MinimumLevel__Default`, and so on. The logs go to the container
  log (console) and to `/data/logs`: the image sets `Serilog__WriteTo__File__Args__path` and
  `Serilog__WriteTo__HtmlFile__Args__path` (see [Log files](../README.md#log-files)).

### HTTPS

The admin UI listens on plain HTTP inside the container. The login cookie is sent in clear text, so do not publish
port 80 to a network you do not trust. Either put a reverse proxy with HTTPS in front of it (bind the port to
`127.0.0.1:8080` as the compose example does), or mount a certificate into the container:

```sh
-e Kestrel__Endpoints__Https__Url=https://0.0.0.0:443 \
-e Kestrel__Endpoints__Https__Certificate__Path=/config/cert.pfx \
-e Kestrel__Endpoints__Https__Certificate__Password=...
```

### Compose

[`deploy/docker-compose.yml`](../deploy/docker-compose.yml) is a single node with a named volume and a read-only root
file system.

## Release archive and systemd

Each release has a self-contained, single-file archive for `linux-x64`, `linux-arm64`, `win-x64` and `osx-arm64`,
and `SHA256SUMS.txt`. An archive has `FxSshSftpServer` (the web host) and `ServerConsoleApp` (the plain SFTP server and
the `user` commands), no .NET installation needed. `--version` prints the release version.

```sh
sha256sum -c SHA256SUMS.txt --ignore-missing
tar -xzf freesftpsharp-1.2.3-linux-x64.tar.gz
sudo freesftpsharp-1.2.3-linux-x64/deploy/systemd/install.sh freesftpsharp-1.2.3-linux-x64.tar.gz
```

[`deploy/systemd/install.sh`](../deploy/systemd/install.sh) creates the `freesftpsharp` user, installs the binaries
to `/opt/freesftpsharp`, writes `/etc/freesftpsharp/freesftpsharp.env` with a generated admin password (printed once)
and the admin UI on `127.0.0.1:5000`, and installs and starts
[`freesftpsharp.service`](../deploy/systemd/freesftpsharp.service). State is in `/var/lib/freesftpsharp`, logs are in
`/var/log/freesftpsharp` (the unit sets `Serilog__WriteTo__File__Args__path` and `Serilog__WriteTo__HtmlFile__Args__path`). The unit gives the process only the capability to bind ports below 1024, and a
read-only file system except for its state and log directories: add the directories of the user roots to
`ReadWritePaths=`. Manage users with `/opt/freesftpsharp/ServerConsoleApp/ServerConsoleApp user ...` using the same
environment (`sudo -u freesftpsharp env ConnectionStrings__Settings="Data Source=/var/lib/freesftpsharp/freesftpsharp.db" ...`).

## Kubernetes

[`deploy/kubernetes/freesftpsharp.yaml`](../deploy/kubernetes/freesftpsharp.yaml) is a StatefulSet with one replica and
a persistent volume, an SFTP `LoadBalancer` Service, a cluster-internal admin Service, probes on `/healthz` and
`/readyz`, and a restricted security context. Run one replica: the settings database is a SQLite file. A multi-node
setup needs #75.

## Upgrade

Take a backup, then replace the image or the binaries. The database schema is migrated at start.

- Container: `docker compose pull && docker compose up -d`, or run the new tag with the same volume. Pin a version
  tag (`X.Y.Z`) in production, not `latest`.
- Archive: run `install.sh` with the new archive; the previous binaries stay in `/opt/freesftpsharp.previous`.

## Backup

Stop the server, or take a SQLite online backup, and copy:

- the settings database (`/data/freesftpsharp.db` or `/var/lib/freesftpsharp/freesftpsharp.db`): users, settings
  and the SSH host keys (`sqlite3 freesftpsharp.db ".backup backup.db"` works while the server runs),
- the `keys/` directory (admin login data protection keys; losing them only logs the admin out),
- the user root directories (the files), by your usual file backup.

The `dump` command of #67 is not available yet.

## Release process (maintainers)

Pushing a tag `vX.Y.Z` runs [`.github/workflows/release.yml`](../.github/workflows/release.yml): it builds the four
archives, builds the image, runs the smoke test and a `trivy` scan (the release stops at a critical finding with a fix)
**before** anything is pushed, pushes the multi-arch image to GHCR with SBOM and provenance, and creates the GitHub
Release with the archives, `SHA256SUMS.txt` and generated notes. The version comes from the tag (`-p:Version`).
A pull request that changes the Dockerfile or the project files runs only
[`docker-check.yml`](../.github/workflows/docker-check.yml): an image build and the same smoke test, nothing is pushed.
