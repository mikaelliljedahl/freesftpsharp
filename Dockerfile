# syntax=docker/dockerfile:1
# FreeSftpSharp container image: the web host (SFTP server + admin UI) and the "user" command line.
#
#   docker build -t freesftpsharp .
#   docker run -p 2222:22 -p 8080:80 -v freesftpsharp-data:/data freesftpsharp
#
# The build runs on the build platform and publishes a portable (not architecture specific) app, so one build
# serves linux/amd64 and linux/arm64 (docker buildx --platform linux/amd64,linux/arm64).

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:11.0 AS build
WORKDIR /src
ARG VERSION=0.0.0-container
ENV DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1

# Restore in locked mode (the build fails if a package would resolve to another version than packages.lock.json).
# The restore needs the whole source tree: the static web assets of the web host add a package to the graph.
# The NuGet cache is a build cache mount, so a rebuild does not download the packages again.
COPY . .
RUN --mount=type=cache,target=/root/.nuget/packages \
    dotnet restore FxSshSftpServer/FxSshSftpServer.csproj --locked-mode \
 && dotnet restore ServerConsoleApp/ServerConsoleApp.csproj --locked-mode \
 && dotnet publish FxSshSftpServer/FxSshSftpServer.csproj -c Release --no-restore -p:Version=${VERSION} -o /out/web \
 && dotnet publish ServerConsoleApp/ServerConsoleApp.csproj -c Release --no-restore -p:Version=${VERSION} -o /out/cli

FROM mcr.microsoft.com/dotnet/aspnet:11.0 AS final
ARG VERSION=0.0.0-container
LABEL org.opencontainers.image.title="FreeSftpSharp" \
      org.opencontainers.image.description="SFTP server with an admin web UI" \
      org.opencontainers.image.source="https://github.com/mikaelliljedahl/freesftpsharp" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

WORKDIR /app
COPY --from=build /out/web ./web
COPY --from=build /out/cli ./cli
# The content root is the working directory: appsettings.json and wwwroot are found there.
WORKDIR /app/web
COPY deploy/docker/entrypoint.sh deploy/docker/healthcheck.sh deploy/docker/freesftpsharp-user /usr/local/bin/

# /data: the settings database (users, settings, SSH host keys), the admin data protection keys, the logs and the
# default user root directories (/app/web/logs, where the relative log paths of appsettings.json end, links to /data/logs). /config: an optional appsettings.Production.json.
# The base image user "app" (UID 1654) owns both; a named volume copies this ownership on first use.
USER root
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh /usr/local/bin/freesftpsharp-user \
 && mkdir -p /data /config \
 && ln -s /config/appsettings.Production.json /app/web/appsettings.Production.json \
 && ln -s /data/logs /app/web/logs \
 && chown -R app:app /data /config
USER app

# Zero configuration: a test server on port 22 (SFTP) and 80 (admin UI and /healthz). The container user may bind
# low ports because container runtimes set net.ipv4.ip_unprivileged_port_start=0.
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_HTTP_PORTS= \
    SshServer__Port=22 \
    Kestrel__Endpoints__Http__Url=http://0.0.0.0:80 \
    ConnectionStrings__Settings="Data Source=/data/freesftpsharp.db" \
    DataProtection__KeysPath=/data/keys \
    Observability__Health__Enabled=true \
    Logging__Console__LogLevel__Default=None \
    Serilog__Using__2=Serilog.Sinks.Console \
    Serilog__WriteTo__2__Name=Console \
    DOTNET_gcServer=0

VOLUME ["/data"]
EXPOSE 22 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/usr/local/bin/healthcheck.sh"]
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
