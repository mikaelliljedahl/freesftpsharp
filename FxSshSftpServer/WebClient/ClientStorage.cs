using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.Users;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The storage of the signed-in user for one request of the web client: the file system from the
    /// <see cref="IFileSystemFactory"/> with the full decorator chain (permissions, quotas, events, connection tracking)
    /// for the protocol HTTP and the connection of the browser session, and the map of the controls. The web client has
    /// no path or permission rules of its own: every operation goes through <see cref="FileSystem"/>.
    /// </summary>
    public sealed class ClientStorage
    {
        public ClientStorage(User user, Guid session, IFileSystem fileSystem, ClientPermissionMap permissions)
        {
            User = user;
            Session = session;
            FileSystem = fileSystem;
            Permissions = permissions;
        }

        public User User { get; }

        /// <summary>The id of the browser session (its connection in the connection registry).</summary>
        public Guid Session { get; }

        public IFileSystem FileSystem { get; }

        public ClientPermissionMap Permissions { get; }

        /// <summary>The entries of a directory, directories first, then by name.</summary>
        public async Task<IReadOnlyList<FileSystemEntry>> ListAsync(string directory, CancellationToken ct)
        {
            var entries = new List<FileSystemEntry>();
            await foreach (var entry in FileSystem.ListAsync(directory, ct))
                entries.Add(entry);
            return entries
                .OrderBy(e => e.IsDirectory ? 0 : 1)
                .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        /// <summary>
        /// The check before an upload starts: whether the file exists, and why the upload would be refused (permissions,
        /// path filters or the disk quota), or null. The decorators check it again for every write.
        /// </summary>
        public async Task<UploadCheck> CheckUploadAsync(string path, long size, CancellationToken ct)
        {
            var normalized = VirtualPath.Normalize(path);
            var directory = VirtualPath.GetParent(normalized);
            if (ValidateName(VirtualPath.GetName(normalized)) is { } nameProblem)
                return new UploadCheck(false, nameProblem);
            var actions = Permissions.For(directory);
            FileSystemEntry existing;
            try
            {
                existing = await FileSystem.StatAsync(normalized, true, ct);
            }
            catch (FileSystemException ex) when (ex.Error is FileSystemError.PermissionDenied)
            {
                return new UploadCheck(false, "You may not upload files here.");
            }
            if (existing is { IsDirectory: true })
                return new UploadCheck(true, "A folder with this name exists.");
            if (existing == null && !actions.Upload)
                return new UploadCheck(false, "You may not upload files here.");
            if (existing != null && !actions.Overwrite)
                return new UploadCheck(true, "The file exists, and you may not overwrite files here.");
            if (!Permissions.IsFileNameAllowed(normalized))
                return new UploadCheck(existing != null, "Files with this name are not allowed here.");

            var space = await GetSpaceAsync(directory, ct);
            var growth = size - (existing?.Size ?? 0);
            if (space != null && growth > 0 && (ulong)growth > space.AvailableBytes)
                return new UploadCheck(existing != null, $"Not enough space: the upload needs {Format(growth)}, {Format((long)space.AvailableBytes)} are free (quota).", QuotaExceeded: true);
            return new UploadCheck(existing != null, null);
        }

        /// <summary>The space of the storage of a directory, or null when the storage does not tell it.</summary>
        public async Task<StorageSpace> GetSpaceAsync(string directory, CancellationToken ct)
        {
            try
            {
                return await FileSystem.GetStorageSpaceAsync(directory, ct);
            }
            catch (FileSystemException)
            {
                return null;
            }
        }

        /// <summary>An error text for a new file or folder name, or null when it is valid.</summary>
        public static string ValidateName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return "Enter a name.";
            if (name is "." or ".." || name.IndexOfAny(['/', '\\', '\0']) >= 0)
                return "A name cannot be '.' or '..' or contain '/' or '\\'.";
            if (name.Length > 255)
                return "A name can have at most 255 characters.";
            return null;
        }

        /// <summary>A byte count for people: "12.3 MiB".</summary>
        public static string Format(long bytes)
        {
            string[] units = ["B", "KiB", "MiB", "GiB", "TiB"];
            double value = bytes;
            var unit = 0;
            while (value >= 1024 && unit < units.Length - 1)
            {
                value /= 1024;
                unit++;
            }
            return unit == 0 ? $"{bytes} B" : $"{value:0.#} {units[unit]}";
        }
    }

    /// <summary>The result of <see cref="ClientStorage.CheckUploadAsync"/>.</summary>
    /// <param name="Exists">True when a file (or folder) with the name exists.</param>
    /// <param name="Problem">Why the upload would be refused, for the user; null when it can start.</param>
    /// <param name="QuotaExceeded">True when the problem is the free space of the quota.</param>
    public sealed record UploadCheck(bool Exists, string Problem, bool QuotaExceeded = false);

    /// <summary>Creates the <see cref="ClientStorage"/> of the signed-in web client user of a request.</summary>
    public sealed class ClientStorageFactory
    {
        private readonly ISettingsRepository _repository;
        private readonly IFileSystemFactory _fileSystems;
        private readonly IEffectiveUserSettingsService _settings;

        public ClientStorageFactory(ISettingsRepository repository, IFileSystemFactory fileSystems, IEffectiveUserSettingsService settings)
        {
            _repository = repository;
            _fileSystems = fileSystems;
            _settings = settings;
        }

        /// <summary>
        /// The storage of the user of <paramref name="context"/>, or null when the request has no web client login (or the
        /// user was removed). Throws <see cref="ArgumentException"/> when the storage configuration of the user is not valid.
        /// </summary>
        public async Task<ClientStorage> CreateAsync(HttpContext context, CancellationToken ct)
        {
            if (ClientClaims.Session(context.User) is not { } session)
                return null;
            var user = _repository.GetUser(context.User.Identity!.Name);
            if (user == null)
                return null;
            var remoteIp = context.Connection.RemoteIpAddress is { } ip ? SshServer.Interfaces.Net.CidrNotation.Normalize(ip).ToString() : null;
            var fileSystem = await _fileSystems.CreateAsync(user, new ClientContext(ClientAuth.Protocol, remoteIp, session), ct);
            var permissions = new ClientPermissionMap(_settings.Resolve(user).Permissions, (fileSystem.Capabilities & StorageCapabilities.CaseInsensitivePaths) != 0);
            return new ClientStorage(user, session, fileSystem, permissions);
        }
    }
}
