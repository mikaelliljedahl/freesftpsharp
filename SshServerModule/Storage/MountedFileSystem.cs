#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Storage
{
    /// <summary>
    /// The file system of a user with virtual folders (issue #56): routes every operation to the storage with the
    /// longest mount path that holds the path, with the path inside that storage. The root storage has "/".
    /// <list type="bullet">
    /// <item>A mount point is a directory in its parent listing, with the attributes of the root of the mounted storage
    /// (or a plain directory when that storage cannot answer, so a broken folder does not break the parent listing).
    /// It hides an entry of the same name in the parent storage.</item>
    /// <item>The parents of a mount point that do not exist (for example "/a" for a mount at "/a/b") are virtual
    /// directories: they are listed and can be listed, but cannot be removed or changed.</item>
    /// <item>A mount point is the root of its storage: it cannot be removed, renamed or replaced
    /// (<see cref="FileSystemError.PermissionDenied"/>). A directory that holds a mount point cannot be removed
    /// (<see cref="FileSystemError.DirectoryNotEmpty"/>), renamed (<see cref="FileSystemError.PermissionDenied"/>) or
    /// replaced (it exists).</item>
    /// <item>A rename between two storages throws <see cref="FileSystemError.OpNotSupported"/>: it would be a copy and a
    /// delete, which is not atomic and can be slow. The client can copy the file itself.</item>
    /// </list>
    /// The storage rules (permissions, events) wrap this class, so they see the virtual paths of the user. An open file is
    /// the handle of its storage itself (not wrapped), so <see cref="IFileHandle.AbortAsync"/> reaches that storage.
    /// <see cref="Capabilities"/> are the capabilities that every storage has, plus <see cref="StorageCapabilities.CaseInsensitivePaths"/>
    /// when one storage has it (so the permission rules match every spelling). Mount paths are compared like the root
    /// storage compares paths.
    /// </summary>
    public sealed class MountedFileSystem : IFileSystem
    {
        /// <summary>A storage mounted at a virtual path.</summary>
        /// <param name="Path">The virtual path, for example "/shared"; not "/".</param>
        /// <param name="FileSystem">The storage; its "/" is <paramref name="Path"/>.</param>
        public sealed record Mount(string Path, IFileSystem FileSystem);

        private static readonly DateTime VirtualDirectoryTime = DateTime.UnixEpoch;
        private const uint VirtualDirectoryPermissions = 0x16D; // r-xr-xr-x

        private readonly IFileSystem _root;
        private readonly Mount[] _mounts; // longest path first
        private readonly StringComparison _comparison;

        public MountedFileSystem(IFileSystem root, IEnumerable<Mount> mounts)
        {
            _root = root ?? throw new ArgumentNullException(nameof(root));
            _comparison = (root.Capabilities & StorageCapabilities.CaseInsensitivePaths) != 0 ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

            var list = new List<Mount>();
            foreach (var mount in mounts ?? throw new ArgumentNullException(nameof(mounts)))
            {
                var path = VirtualPath.Normalize(mount.Path);
                if (path == VirtualPath.Root)
                    throw new ArgumentException("A virtual folder cannot be mounted at /.", nameof(mounts));
                if (list.Any(m => string.Equals(m.Path, path, _comparison)))
                    throw new ArgumentException($"Two virtual folders are mounted at {path}.", nameof(mounts));
                list.Add(new Mount(path, mount.FileSystem ?? throw new ArgumentException($"The storage of {path} is null.", nameof(mounts))));
            }
            _mounts = list.OrderByDescending(m => m.Path.Length).ToArray();

            var all = _mounts.Select(m => m.FileSystem.Capabilities).Prepend(root.Capabilities).ToArray();
            var common = all.Aggregate((a, b) => a & b);
            Capabilities = all.Any(c => (c & StorageCapabilities.CaseInsensitivePaths) != 0)
                ? common | StorageCapabilities.CaseInsensitivePaths
                : common;
        }

        public StorageCapabilities Capabilities { get; }

        public async ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct)
        {
            var target = Route(path);
            if (target.IsMountPoint)
            {
                var entry = await target.FileSystem.StatAsync(VirtualPath.Root, followLinks, ct);
                return entry is null ? null : entry with { Name = VirtualPath.GetName(target.Path) };
            }

            var found = await target.FileSystem.StatAsync(target.InnerPath, followLinks, ct);
            if (IsParentOfMount(target.Path) && found is not { IsDirectory: true })
                return VirtualDirectory(target.Path);
            return found;
        }

        public async IAsyncEnumerable<FileSystemEntry> ListAsync(string path, [EnumeratorCancellation] CancellationToken ct)
        {
            var target = Route(path);
            var overlay = MountChildren(target.Path);
            if (overlay.Count == 0)
            {
                await foreach (var entry in target.FileSystem.ListAsync(target.InnerPath, ct))
                    yield return entry;
                yield break;
            }

            var names = new HashSet<string>(overlay, Comparer);
            var entries = new List<FileSystemEntry>();
            await using (var enumerator = target.FileSystem.ListAsync(target.InnerPath, ct).GetAsyncEnumerator(ct))
            {
                while (true)
                {
                    try
                    {
                        if (!await enumerator.MoveNextAsync())
                            break;
                    }
                    catch (FileSystemException ex) when (ex.Error is FileSystemError.NoSuchFile or FileSystemError.NotADirectory)
                    {
                        break; // a virtual parent of a mount point: only the mounts are in it
                    }
                    if (!names.Contains(enumerator.Current.Name))
                        entries.Add(enumerator.Current);
                }
            }

            foreach (var entry in entries)
                yield return entry;
            foreach (var name in overlay)
                yield return await MountEntryAsync(VirtualPath.Combine(target.Path, name), ct);
        }

        public ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct)
        {
            var target = Route(path);
            if (target.IsMountPoint || IsParentOfMount(target.Path))
                throw new FileSystemException(FileSystemError.IsADirectory, $"{target.Path} is a directory.");
            return target.FileSystem.OpenAsync(target.InnerPath, flags, initial, ct);
        }

        public ValueTask CreateDirectoryAsync(string path, CancellationToken ct)
        {
            var target = Route(path);
            if (target.IsMountPoint || IsParentOfMount(target.Path))
                throw new FileSystemException(FileSystemError.AlreadyExists, $"{target.Path} already exists.");
            return target.FileSystem.CreateDirectoryAsync(target.InnerPath, ct);
        }

        public ValueTask DeleteFileAsync(string path, CancellationToken ct)
        {
            var target = Route(path);
            if (target.IsMountPoint || IsParentOfMount(target.Path))
                throw new FileSystemException(FileSystemError.IsADirectory, $"{target.Path} is a directory.");
            return target.FileSystem.DeleteFileAsync(target.InnerPath, ct);
        }

        public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct)
        {
            var target = Route(path);
            if (target.IsMountPoint)
                throw new FileSystemException(FileSystemError.PermissionDenied, $"{target.Path} is a virtual folder and cannot be removed.");
            if (IsParentOfMount(target.Path))
                throw new FileSystemException(FileSystemError.DirectoryNotEmpty, $"{target.Path} holds a virtual folder.");
            return target.FileSystem.DeleteDirectoryAsync(target.InnerPath, ct);
        }

        public async ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct)
        {
            var source = Route(oldPath);
            var target = Route(newPath);
            if (source.IsMountPoint || IsParentOfMount(source.Path))
                throw new FileSystemException(FileSystemError.PermissionDenied, $"{source.Path} is or holds a virtual folder and cannot be moved.");
            if (target.IsMountPoint)
                throw new FileSystemException(FileSystemError.PermissionDenied, $"{target.Path} is a virtual folder and cannot be replaced.");
            if (IsParentOfMount(target.Path))
            {
                var entry = await source.FileSystem.StatAsync(source.InnerPath, followLinks: false, ct)
                            ?? throw new FileSystemException(FileSystemError.NoSuchFile, $"{source.Path} does not exist.");
                if ((flags & RenameFlags.ReplaceExisting) != 0 && !entry.IsDirectory)
                    throw new FileSystemException(FileSystemError.IsADirectory, $"{target.Path} is a directory.");
                throw new FileSystemException(FileSystemError.AlreadyExists, $"{target.Path} already exists.");
            }
            if (!ReferenceEquals(source.FileSystem, target.FileSystem))
                throw new FileSystemException(FileSystemError.OpNotSupported,
                    $"{source.Path} and {target.Path} are in different storages (virtual folders); copy the file instead.");
            await source.FileSystem.RenameAsync(source.InnerPath, target.InnerPath, flags, ct);
        }

        public async ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct)
        {
            var target = Route(path);
            if (!target.IsMountPoint && IsParentOfMount(target.Path)
                && await target.FileSystem.StatAsync(target.InnerPath, followLinks: true, ct) is not { IsDirectory: true })
            {
                if (update.IsEmpty)
                    return;
                throw new FileSystemException(FileSystemError.PermissionDenied, $"{target.Path} is a virtual directory and cannot be changed.");
            }
            await target.FileSystem.SetAttributesAsync(target.InnerPath, update, ct);
        }

        public async ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct)
        {
            var target = Route(path);
            if (!target.IsMountPoint && IsParentOfMount(target.Path)
                && await target.FileSystem.StatAsync(target.InnerPath, followLinks: true, ct) is not { IsDirectory: true })
                return null; // a virtual directory has no storage of its own
            return await target.FileSystem.GetStorageSpaceAsync(target.InnerPath, ct);
        }

        private StringComparer Comparer => _comparison == StringComparison.Ordinal ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase;

        /// <summary>A normalized path, its storage and the path in that storage.</summary>
        private readonly record struct Target(string Path, IFileSystem FileSystem, string InnerPath, bool IsMountPoint);

        private Target Route(string path)
        {
            var normalized = VirtualPath.Normalize(path);
            foreach (var mount in _mounts)
            {
                if (string.Equals(normalized, mount.Path, _comparison))
                    return new Target(normalized, mount.FileSystem, VirtualPath.Root, IsMountPoint: true);
                if (normalized.Length > mount.Path.Length && normalized[mount.Path.Length] == '/'
                    && normalized.StartsWith(mount.Path, _comparison))
                    return new Target(normalized, mount.FileSystem, normalized.Substring(mount.Path.Length), IsMountPoint: false);
            }
            return new Target(normalized, _root, normalized, IsMountPoint: false);
        }

        /// <summary>True when a mount point is below <paramref name="normalizedPath"/>.</summary>
        private bool IsParentOfMount(string normalizedPath) => MountChildren(normalizedPath).Count > 0;

        /// <summary>The names in <paramref name="directory"/> that are mount points or virtual parents of mount points.</summary>
        private List<string> MountChildren(string directory)
        {
            var prefix = directory == VirtualPath.Root ? VirtualPath.Root : directory + "/";
            var names = new List<string>();
            foreach (var mount in _mounts)
            {
                if (mount.Path.Length <= prefix.Length || !mount.Path.StartsWith(prefix, _comparison))
                    continue;
                var rest = mount.Path.Substring(prefix.Length);
                var slash = rest.IndexOf('/');
                var name = slash < 0 ? rest : rest.Substring(0, slash);
                if (!names.Contains(name, Comparer))
                    names.Add(name);
            }
            return names;
        }

        /// <summary>The entry of a mount point or a virtual parent in a listing; a plain directory when its storage fails.</summary>
        private async ValueTask<FileSystemEntry> MountEntryAsync(string path, CancellationToken ct)
        {
            try
            {
                return await StatAsync(path, followLinks: true, ct) ?? VirtualDirectory(path);
            }
            catch (FileSystemException)
            {
                return VirtualDirectory(path);
            }
        }

        private static FileSystemEntry VirtualDirectory(string path)
            => new(VirtualPath.GetName(path), FileSystemEntryType.Directory, 0, VirtualDirectoryTime, VirtualDirectoryTime)
            {
                Permissions = VirtualDirectoryPermissions,
            };
    }
}
