using System.Runtime.CompilerServices;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage;

/// <summary>
/// An <see cref="IFileSystem"/> in memory, for tests only (it does not ship with the server): the second backend
/// of the conformance suite, and the test double for the SFTP adapter and for the storage decorators.
/// <para>
/// The capabilities are a constructor parameter. Without <see cref="StorageCapabilities.RandomAccessWrite"/> it
/// behaves like an object store: a handle accepts only writes at the current end of the file and the size cannot
/// be changed. Without another capability the operations that need it throw <see cref="FileSystemError.OpNotSupported"/>.
/// </para>
/// <para>
/// An open handle keeps its file: after a rename it writes to the renamed file, after a delete it writes to a file
/// that nobody sees (like POSIX). All members are thread safe (one lock).
/// </para>
/// </summary>
public sealed class InMemoryFileSystem : IFileSystem
{
    /// <summary>Every capability that this class can have.</summary>
    public const StorageCapabilities AllCapabilities = StorageCapabilities.RandomAccessWrite | StorageCapabilities.Append
        | StorageCapabilities.Rename | StorageCapabilities.SetTimes | StorageCapabilities.SetPermissions;

    private const uint DefaultFilePermissions = 0x1A4;      // rw-r--r--
    private const uint DefaultDirectoryPermissions = 0x1ED; // rwxr-xr-x

    private readonly object _lock = new();
    private readonly Dictionary<string, Node> _nodes = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;

    public InMemoryFileSystem(StorageCapabilities capabilities = AllCapabilities, TimeProvider? time = null)
    {
        if ((capabilities & ~AllCapabilities) != 0)
            throw new ArgumentException($"Not supported by {nameof(InMemoryFileSystem)}: {capabilities & ~AllCapabilities}.", nameof(capabilities));
        Capabilities = capabilities;
        _time = time ?? TimeProvider.System;
        _nodes[VirtualPath.Root] = new Node(isDirectory: true, DefaultDirectoryPermissions, Now);
    }

    public StorageCapabilities Capabilities { get; }

    private DateTime Now => _time.GetUtcNow().UtcDateTime;

    public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        lock (_lock)
            return ValueTask.FromResult(_nodes.TryGetValue(normalized, out var node) ? node.ToEntry(VirtualPath.GetName(normalized)) : null);
    }

    public async IAsyncEnumerable<FileSystemEntry> ListAsync(string path, [EnumeratorCancellation] CancellationToken ct)
    {
        await Task.CompletedTask;
        ct.ThrowIfCancellationRequested();
        var directory = VirtualPath.Normalize(path);
        List<FileSystemEntry> entries;
        lock (_lock)
        {
            var node = Find(directory, path);
            if (!node.IsDirectory)
                throw new FileSystemException(FileSystemError.NotADirectory, $"Not a directory: {path}");

            entries = _nodes
                .Where(n => n.Key != VirtualPath.Root && VirtualPath.GetParent(n.Key) == directory)
                .Select(n => n.Value.ToEntry(VirtualPath.GetName(n.Key)))
                .ToList();
        }

        foreach (var entry in entries)
            yield return entry;
    }

    public ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        if ((flags & FileOpenFlags.Append) != 0)
            Require(StorageCapabilities.Append, path);

        lock (_lock)
        {
            if (_nodes.TryGetValue(normalized, out var node))
            {
                if (node.IsDirectory)
                    throw new FileSystemException(FileSystemError.IsADirectory, $"Is a directory: {path}");
                if ((flags & (FileOpenFlags.Create | FileOpenFlags.Exclusive)) == (FileOpenFlags.Create | FileOpenFlags.Exclusive))
                    throw new FileSystemException(FileSystemError.AlreadyExists, $"Already exists: {path}");
                if ((flags & (FileOpenFlags.Create | FileOpenFlags.Truncate)) == (FileOpenFlags.Create | FileOpenFlags.Truncate))
                    node.SetLength(0, Now);
            }
            else
            {
                if ((flags & FileOpenFlags.Create) == 0)
                    throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");
                RequireParentDirectory(normalized, path);
                node = new Node(isDirectory: false, DefaultFilePermissions, Now);
                if (initial?.Permissions is { } permissions)
                    node.Permissions = permissions & 0x1FF;
                _nodes[normalized] = node;
            }

            return ValueTask.FromResult<IFileHandle>(new Handle(this, node, VirtualPath.GetName(normalized), path, flags));
        }
    }

    public ValueTask CreateDirectoryAsync(string path, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        lock (_lock)
        {
            if (_nodes.ContainsKey(normalized))
                throw new FileSystemException(FileSystemError.AlreadyExists, $"Already exists: {path}");
            RequireParentDirectory(normalized, path);
            _nodes[normalized] = new Node(isDirectory: true, DefaultDirectoryPermissions, Now);
        }
        return ValueTask.CompletedTask;
    }

    public ValueTask DeleteFileAsync(string path, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        lock (_lock)
        {
            if (Find(normalized, path).IsDirectory)
                throw new FileSystemException(FileSystemError.IsADirectory, $"Is a directory: {path}");
            _nodes.Remove(normalized);
        }
        return ValueTask.CompletedTask;
    }

    public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        lock (_lock)
        {
            if (normalized == VirtualPath.Root)
                throw new FileSystemException(FileSystemError.PermissionDenied, "The user root directory cannot be removed.");
            if (!Find(normalized, path).IsDirectory)
                throw new FileSystemException(FileSystemError.NotADirectory, $"Not a directory: {path}");
            if (_nodes.Keys.Any(key => IsBelow(key, normalized)))
                throw new FileSystemException(FileSystemError.DirectoryNotEmpty, $"The directory is not empty: {path}");
            _nodes.Remove(normalized);
        }
        return ValueTask.CompletedTask;
    }

    public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Require(StorageCapabilities.Rename, oldPath);
        var source = VirtualPath.Normalize(oldPath);
        var target = VirtualPath.Normalize(newPath);
        lock (_lock)
        {
            if (source == VirtualPath.Root || target == VirtualPath.Root)
                throw new FileSystemException(FileSystemError.PermissionDenied, "The user root directory cannot be moved or replaced.");
            var node = Find(source, oldPath);
            RequireParentDirectory(target, newPath);
            if (source == target)
                return ValueTask.CompletedTask; // rename(2) of a path to itself does nothing
            if (node.IsDirectory && IsBelow(target, source))
                throw new FileSystemException(FileSystemError.Failure, $"Cannot move a directory into itself: {newPath}");

            if (_nodes.TryGetValue(target, out var existing))
            {
                if ((flags & RenameFlags.ReplaceExisting) == 0 || node.IsDirectory)
                    throw new FileSystemException(FileSystemError.AlreadyExists, $"The target already exists: {newPath}");
                if (existing.IsDirectory)
                    throw new FileSystemException(FileSystemError.IsADirectory, $"The target is a directory: {newPath}");
            }

            var moved = _nodes.Where(n => n.Key == source || IsBelow(n.Key, source)).ToList();
            foreach (var (key, _) in moved)
                _nodes.Remove(key);
            foreach (var (key, value) in moved)
                _nodes[target + key.Substring(source.Length)] = value;
        }
        return ValueTask.CompletedTask;
    }

    public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        lock (_lock)
            Apply(Find(normalized, path), normalized == VirtualPath.Root, update, path);
        return ValueTask.CompletedTask;
    }

    public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        lock (_lock)
            Find(VirtualPath.Normalize(path), path);
        return ValueTask.FromResult<StorageSpace?>(null); // memory has no fixed size
    }

    private void Apply(Node node, bool isRoot, FileAttributesUpdate update, string path)
    {
        if (update.Size != null)
            Require(StorageCapabilities.RandomAccessWrite, path);
        if (update.Permissions != null)
            Require(StorageCapabilities.SetPermissions, path);
        if (update.HasTimes)
            Require(StorageCapabilities.SetTimes, path);
        if (update.Permissions != null && isRoot)
            throw new FileSystemException(FileSystemError.PermissionDenied, "The permissions of the user root directory cannot be changed.");

        if (update.Size is { } size)
        {
            if (node.IsDirectory)
                throw new FileSystemException(FileSystemError.IsADirectory, $"Is a directory: {path}");
            if (size < 0)
                throw new FileSystemException(FileSystemError.Failure, $"Invalid size: {path}");
            node.SetLength(size, Now);
        }
        if (update.Permissions is { } permissions)
            node.Permissions = permissions & 0x1FF;
        if (update.LastAccessTimeUtc is { } accessed)
            node.LastAccess = accessed;
        if (update.LastWriteTimeUtc is { } written)
            node.LastWrite = written;
    }

    /// <summary>The node at a normalized path; <see cref="FileSystemError.NoSuchFile"/> when it does not exist. Call with the lock.</summary>
    private Node Find(string normalized, string path)
        => _nodes.TryGetValue(normalized, out var node) ? node : throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");

    /// <summary>The parent of a new entry must be a directory. Call with the lock.</summary>
    private void RequireParentDirectory(string normalized, string path)
    {
        if (!_nodes.TryGetValue(VirtualPath.GetParent(normalized), out var parent))
            throw new FileSystemException(FileSystemError.NoSuchFile, $"No such directory: {path}/..");
        if (!parent.IsDirectory)
            throw new FileSystemException(FileSystemError.NotADirectory, $"Not a directory: {path}/..");
    }

    private void Require(StorageCapabilities capability, string path)
    {
        if ((Capabilities & capability) == 0)
            throw new FileSystemException(FileSystemError.OpNotSupported, $"The storage does not support {capability}: {path}");
    }

    private static bool IsBelow(string path, string directory)
        => path.StartsWith(directory == VirtualPath.Root ? VirtualPath.Root : directory + "/", StringComparison.Ordinal) && path != directory;

    private sealed class Node(bool isDirectory, uint permissions, DateTime created)
    {
        private byte[] _data = [];

        public bool IsDirectory { get; } = isDirectory;
        public long Length { get; private set; }
        public uint Permissions { get; set; } = permissions;
        public DateTime LastWrite { get; set; } = created;
        public DateTime LastAccess { get; set; } = created;

        public FileSystemEntry ToEntry(string name)
            => new(name, IsDirectory ? FileSystemEntryType.Directory : FileSystemEntryType.File, Length, LastWrite, LastAccess) { Permissions = Permissions };

        public int Read(long offset, Span<byte> buffer)
        {
            if (offset >= Length)
                return 0;
            var count = (int)Math.Min(buffer.Length, Length - offset);
            _data.AsSpan((int)offset, count).CopyTo(buffer);
            return count;
        }

        public void Write(long offset, ReadOnlySpan<byte> data, DateTime now)
        {
            var end = offset + data.Length;
            EnsureCapacity(end);
            data.CopyTo(_data.AsSpan((int)offset));
            Length = Math.Max(Length, end);
            LastWrite = now;
        }

        public void SetLength(long length, DateTime now)
        {
            EnsureCapacity(length);
            if (length < Length)
                _data.AsSpan((int)length, (int)(Length - length)).Clear(); // a later extension gives zeros
            Length = length;
            LastWrite = now;
        }

        private void EnsureCapacity(long length)
        {
            if (length > Array.MaxLength)
                throw new FileSystemException(FileSystemError.QuotaExceeded, "The file is too large for memory.");
            if (length > _data.Length)
                Array.Resize(ref _data, (int)Math.Min(Array.MaxLength, Math.Max(length, 2L * _data.Length)));
        }
    }

    private sealed class Handle(InMemoryFileSystem owner, Node node, string name, string path, FileOpenFlags flags) : IFileHandle
    {
        private bool _disposed;

        public ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Check(FileOpenFlags.Read);
            lock (owner._lock)
                return ValueTask.FromResult(node.Read(offset, buffer.Span));
        }

        public ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Check(FileOpenFlags.Write);
            lock (owner._lock)
            {
                if ((flags & FileOpenFlags.Append) != 0)
                    offset = node.Length;
                else if (offset != node.Length && (owner.Capabilities & StorageCapabilities.RandomAccessWrite) == 0)
                    throw new FileSystemException(FileSystemError.OpNotSupported, $"The storage accepts only sequential writes: {path}");
                node.Write(offset, data.Span, owner.Now);
            }
            return ValueTask.CompletedTask;
        }

        public ValueTask FlushAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Check(FileOpenFlags.None);
            return ValueTask.CompletedTask;
        }

        public ValueTask<FileSystemEntry> StatAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Check(FileOpenFlags.None);
            lock (owner._lock)
                return ValueTask.FromResult(node.ToEntry(name));
        }

        public ValueTask SetAttributesAsync(FileAttributesUpdate update, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Check(FileOpenFlags.None);
            lock (owner._lock)
                owner.Apply(node, isRoot: false, update, path);
            return ValueTask.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            _disposed = true;
            return ValueTask.CompletedTask;
        }

        private void Check(FileOpenFlags access)
        {
            if (_disposed)
                throw new FileSystemException(FileSystemError.Failure, $"The file is closed: {path}");
            if ((flags & access) != access)
                throw new FileSystemException(FileSystemError.PermissionDenied, $"The file is not open for {access}: {path}");
        }
    }
}
