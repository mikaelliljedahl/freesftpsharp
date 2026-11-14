#nullable enable
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Storage
{
    /// <summary>
    /// The storage rule "per-path permissions and path filters" (issue #59): an <see cref="IFileSystem"/> decorator that
    /// checks every operation against the <see cref="EffectivePermissions"/> of the user before it reaches the backend.
    /// <para>
    /// An entry gets the permissions of the directory that holds it; a listing gets the permissions of the listed
    /// directory. So with "/incoming = Upload" a user can upload "/incoming/a.txt" but not list "/incoming", and
    /// "/incoming" itself is visible with the permissions of "/".
    /// </para>
    /// <list type="table">
    /// <item><term>Stat, storage space, empty set-attributes</term><description>any permission: a client must see the
    /// file that it may download or overwrite (OpenSSH <c>get</c> stats first), but with <see cref="FilePermissions.None"/>
    /// nothing is visible</description></item>
    /// <item><term>List</term><description><see cref="FilePermissions.List"/> in the directory itself</description></item>
    /// <item><term>Open for reading</term><description><see cref="FilePermissions.Download"/></description></item>
    /// <item><term>Open for writing</term><description><see cref="FilePermissions.Upload"/> for a new file, <see cref="FilePermissions.Overwrite"/> for an existing one</description></item>
    /// <item><term>Create directory</term><description><see cref="FilePermissions.CreateDirectories"/></description></item>
    /// <item><term>Delete file or directory</term><description><see cref="FilePermissions.Delete"/></description></item>
    /// <item><term>Rename</term><description><see cref="FilePermissions.Rename"/> in both directories, and <see cref="FilePermissions.Overwrite"/> in the target directory to replace a file</description></item>
    /// <item><term>Set attributes</term><description>size: <see cref="FilePermissions.Overwrite"/>, mode: <see cref="FilePermissions.ChangeMode"/>, times: <see cref="FilePermissions.ChangeTimes"/></description></item>
    /// </list>
    /// <para>
    /// The decorator itself throws only <see cref="FileSystemError.PermissionDenied"/> and, for a hidden name,
    /// <see cref="FileSystemError.NoSuchFile"/>; errors of the backend pass through unchanged. A refused operation never
    /// reaches the backend.
    /// </para>
    /// </summary>
    public sealed class PermissionFileSystem : IFileSystem
    {
        private readonly IFileSystem _inner;
        private readonly PathRuleResolver _rules;

        public PermissionFileSystem(IFileSystem inner, EffectivePermissions permissions)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _rules = new PathRuleResolver(permissions, (inner.Capabilities & StorageCapabilities.CaseInsensitivePaths) != 0);
        }

        /// <summary>The decorator around <paramref name="inner"/>, or <paramref name="inner"/> itself when the user may do everything.</summary>
        public static IFileSystem Wrap(IFileSystem inner, EffectivePermissions permissions)
            => permissions.IsUnrestricted ? inner : new PermissionFileSystem(inner, permissions);

        public StorageCapabilities Capabilities => _inner.Capabilities;

        public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct)
        {
            var normalized = VirtualPath.Normalize(path);
            if (_rules.IsHidden(normalized))
                return ValueTask.FromResult<FileSystemEntry?>(null);
            RequireAny(ParentOf(normalized), normalized);
            return _inner.StatAsync(normalized, followLinks, ct);
        }

        public async IAsyncEnumerable<FileSystemEntry> ListAsync(string path, [EnumeratorCancellation] CancellationToken ct)
        {
            // An iterator runs at the first MoveNextAsync, as the contract of ListAsync says for its errors.
            var normalized = VirtualPath.Normalize(path);
            ThrowIfHidden(normalized);
            Require(FilePermissions.List, normalized, normalized);
            await foreach (var entry in _inner.ListAsync(normalized, ct).WithCancellation(ct))
            {
                if (!_rules.IsHidden(VirtualPath.Combine(normalized, entry.Name)))
                    yield return entry;
            }
        }

        public async ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct)
        {
            var normalized = VirtualPath.Normalize(path);
            ThrowIfHidden(normalized);
            var directory = ParentOf(normalized);
            var granted = _rules.PermissionsOf(directory);

            if ((flags & FileOpenFlags.Read) != 0)
                Require(FilePermissions.Download, granted, normalized);

            var writes = (flags & (FileOpenFlags.Write | FileOpenFlags.Append | FileOpenFlags.Create | FileOpenFlags.Truncate | FileOpenFlags.Exclusive)) != 0;
            if (writes)
            {
                var mayUpload = (granted & FilePermissions.Upload) != 0;
                var mayOverwrite = (granted & FilePermissions.Overwrite) != 0;
                if (!mayUpload && !mayOverwrite)
                    throw Denied(normalized);

                if (!(mayUpload && mayOverwrite))
                {
                    // Only one of the two: the existence of the file decides which one is needed.
                    var exists = (flags & FileOpenFlags.Exclusive) == 0 && await _inner.StatAsync(normalized, true, ct) != null;
                    if (exists)
                    {
                        Require(FilePermissions.Overwrite, granted, normalized);
                    }
                    else
                    {
                        Require(FilePermissions.Upload, granted, normalized);
                        // Without Overwrite a file that another client creates after the check must not be replaced:
                        // an exclusive create fails with AlreadyExists instead.
                        if (!mayOverwrite && (flags & FileOpenFlags.Create) != 0)
                            flags |= FileOpenFlags.Exclusive;
                    }
                }
            }

            RequireAllowedFileName(normalized);
            var handle = await _inner.OpenAsync(normalized, flags, initial, ct);
            return new Handle(handle, this, normalized);
        }

        public ValueTask CreateDirectoryAsync(string path, CancellationToken ct)
        {
            var normalized = VirtualPath.Normalize(path);
            ThrowIfHidden(normalized);
            Require(FilePermissions.CreateDirectories, ParentOf(normalized), normalized);
            return _inner.CreateDirectoryAsync(normalized, ct);
        }

        public ValueTask DeleteFileAsync(string path, CancellationToken ct)
        {
            var normalized = VirtualPath.Normalize(path);
            ThrowIfHidden(normalized);
            Require(FilePermissions.Delete, ParentOf(normalized), normalized);
            RequireAllowedFileName(normalized);
            return _inner.DeleteFileAsync(normalized, ct);
        }

        public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct)
        {
            var normalized = VirtualPath.Normalize(path);
            ThrowIfHidden(normalized);
            Require(FilePermissions.Delete, ParentOf(normalized), normalized);
            return _inner.DeleteDirectoryAsync(normalized, ct);
        }

        public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct)
        {
            var source = VirtualPath.Normalize(oldPath);
            var target = VirtualPath.Normalize(newPath);
            ThrowIfHidden(source);
            ThrowIfHidden(target);
            Require(FilePermissions.Rename, ParentOf(source), source);
            Require(FilePermissions.Rename, ParentOf(target), target);

            // A rename moves everything below the source. If rules exist for the source or the target (or below them),
            // the move would take entries out of their rules or put them under other ones.
            if (_rules.HasRulesAtOrBelow(source) || _rules.HasRulesAtOrBelow(target))
                throw Denied(source);

            // The patterns are for files: a directory may have and get any name.
            if (!_rules.IsFileNameAllowed(source) || !_rules.IsFileNameAllowed(target))
                return RenameIfDirectoryAsync(source, target, flags, ct);

            // Without Overwrite in the target directory an existing file there is not replaced: the backend fails with AlreadyExists.
            if ((_rules.PermissionsOf(ParentOf(target)) & FilePermissions.Overwrite) == 0)
                flags &= ~RenameFlags.ReplaceExisting;
            return _inner.RenameAsync(source, target, flags, ct);
        }

        private async ValueTask RenameIfDirectoryAsync(string source, string target, RenameFlags flags, CancellationToken ct)
        {
            if (await _inner.StatAsync(source, false, ct) is not { IsDirectory: true })
                throw Denied(target);
            // Replacing is not possible for a directory, so the flag does not matter here.
            await _inner.RenameAsync(source, target, flags & ~RenameFlags.ReplaceExisting, ct);
        }

        public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct)
        {
            var normalized = VirtualPath.Normalize(path);
            ThrowIfHidden(normalized);
            RequireForUpdate(update, ParentOf(normalized), normalized);
            return _inner.SetAttributesAsync(normalized, update, ct);
        }

        public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct)
        {
            var normalized = VirtualPath.Normalize(path);
            ThrowIfHidden(normalized);
            RequireAny(ParentOf(normalized), normalized);
            return _inner.GetStorageSpaceAsync(normalized, ct);
        }

        private void RequireForUpdate(FileAttributesUpdate update, string directory, string path)
        {
            var needed = FilePermissions.None;
            if (update.Size != null)
                needed |= FilePermissions.Overwrite;
            if (update.Permissions != null)
                needed |= FilePermissions.ChangeMode;
            if (update.HasTimes)
                needed |= FilePermissions.ChangeTimes;
            if (needed == FilePermissions.None)
                RequireAny(directory, path);
            else
                Require(needed, directory, path);
        }

        /// <summary>The directory whose permissions apply to an entry; for the root, the root.</summary>
        private static string ParentOf(string normalizedPath) => VirtualPath.GetParent(normalizedPath);

        private void Require(FilePermissions needed, string directory, string path)
            => Require(needed, _rules.PermissionsOf(directory), path);

        private static void Require(FilePermissions needed, FilePermissions granted, string path)
        {
            if ((granted & needed) != needed)
                throw Denied(path);
        }

        /// <summary>Some permission in <paramref name="directory"/>: enough to see the attributes of an entry in it.</summary>
        private void RequireAny(string directory, string path)
        {
            if (_rules.PermissionsOf(directory) == FilePermissions.None)
                throw Denied(path);
        }

        private void RequireAllowedFileName(string path)
        {
            if (!_rules.IsFileNameAllowed(path))
                throw Denied(path);
        }

        private void ThrowIfHidden(string path)
        {
            if (_rules.IsHidden(path))
                throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");
        }

        private static FileSystemException Denied(string path)
            => new(FileSystemError.PermissionDenied, $"Permission denied: {path}");

        /// <summary>An open file: reads and writes were checked by the open flags; a change of the attributes is checked here.</summary>
        private sealed class Handle : IFileHandle
        {
            private readonly IFileHandle _inner;
            private readonly PermissionFileSystem _owner;
            private readonly string _path;

            public Handle(IFileHandle inner, PermissionFileSystem owner, string path)
            {
                _inner = inner;
                _owner = owner;
                _path = path;
            }

            public ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken ct) => _inner.ReadAsync(offset, buffer, ct);

            public ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct) => _inner.WriteAsync(offset, data, ct);

            public ValueTask FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);

            public ValueTask<FileSystemEntry> StatAsync(CancellationToken ct) => _inner.StatAsync(ct);

            public ValueTask SetAttributesAsync(FileAttributesUpdate update, CancellationToken ct)
            {
                // An empty update through an open handle needs nothing: the file is already open.
                if (!update.IsEmpty)
                    _owner.RequireForUpdate(update, ParentOf(_path), _path);
                return _inner.SetAttributesAsync(update, ct);
            }

            public ValueTask DisposeAsync() => _inner.DisposeAsync();

            public ValueTask AbortAsync() => _inner.AbortAsync();
        }
    }
}
