using System.Runtime.CompilerServices;
using Amazon.S3;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.S3;

/// <summary>
/// One user's storage in an S3 bucket (or below a key prefix in it).
/// <para>
/// Directories are virtual: a directory exists when an object key starts with its prefix ("dir/"). A new directory is a
/// zero-byte marker object "dir/", so an empty directory stays; removing the last file of a directory without a marker
/// (one that another tool wrote) makes the directory disappear. Listings use ListObjectsV2 with the delimiter "/", page
/// by page, and the common prefixes are the directories. A directory has the time of its marker, or 1970-01-01 (also in
/// a listing, which has no time for a common prefix).
/// </para>
/// <para>
/// Files: reads are ranged GetObject requests through a read-ahead buffer (<see cref="S3ReadBuffer"/>); writes are
/// sequential, streamed as a multipart upload (<see cref="S3Upload"/>), and the object appears when the file is closed.
/// A rename is a copy on the server and a delete (for a directory: of every object below it), not atomic. There are no
/// POSIX permissions, no settable times and no links; <see cref="StorageCapabilities"/> says so, and those changes throw
/// <see cref="FileSystemError.OpNotSupported"/>. A change that changes nothing (an empty update, the current size) works.
/// </para>
/// </summary>
public sealed class S3FileSystem : IFileSystem
{
    private static readonly FileSystemEntry RootEntry = Directory(VirtualPath.Root, DateTime.UnixEpoch);

    private readonly S3ObjectStore _store;
    private readonly S3KeyMapper _keys;

    public S3FileSystem(IAmazonS3 client, S3StorageOptions options)
        : this(new S3ObjectStore(client, options))
    {
    }

    internal S3FileSystem(S3ObjectStore store)
    {
        _store = store;
        _keys = new S3KeyMapper(store.Options.KeyPrefix);
    }

    /// <summary>
    /// Sequential writes, also at the end of an existing file (a resumed upload or an append, by a copy on the server),
    /// rename (by copy and delete) and the copy on the server.
    /// </summary>
    public StorageCapabilities Capabilities => StorageCapabilities.Append | StorageCapabilities.Rename | StorageCapabilities.ServerSideCopy;

    public async ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        return await S3Errors.RunAsync(path, () => StatCoreAsync(normalized, ct), ct).ConfigureAwait(false);
    }

    public async IAsyncEnumerable<FileSystemEntry> ListAsync(string path, [EnumeratorCancellation] CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        var prefix = _keys.DirectoryPrefix(normalized);
        var found = normalized == VirtualPath.Root;
        string? token = null;
        do
        {
            var page = await S3Errors.RunAsync(path, () => _store.ListPageAsync(prefix, "/", token, maxKeys: null, ct), ct).ConfigureAwait(false);
            var directories = page.CommonPrefixes ?? [];
            var files = page.S3Objects ?? [];
            if (!found && directories.Count == 0 && files.Count == 0)
            {
                var isFile = await S3Errors.RunAsync(path, async () => await _store.HeadAsync(_keys.FileKey(normalized), ct).ConfigureAwait(false) != null, ct).ConfigureAwait(false);
                throw isFile
                    ? new FileSystemException(FileSystemError.NotADirectory, $"Not a directory: {path}")
                    : new FileSystemException(FileSystemError.NoSuchFile, $"No such directory: {path}");
            }
            found = true;

            foreach (var directory in directories)
            {
                if (S3KeyMapper.ChildName(prefix, directory) is { } name)
                    yield return Directory(name, DateTime.UnixEpoch);
            }
            foreach (var file in files)
            {
                if (!file.Key.EndsWith('/') && S3KeyMapper.ChildName(prefix, file.Key) is { } name)
                    yield return File(name, new S3ObjectInfo(file.Size ?? 0, S3ObjectStore.ToUtc(file.LastModified), file.ETag));
            }
            token = page.IsTruncated == true ? page.NextContinuationToken : null;
        }
        while (token != null);
    }

    public async ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        if (normalized == VirtualPath.Root)
            throw new FileSystemException(FileSystemError.IsADirectory, $"Is a directory: {path}");
        if ((flags & (FileOpenFlags.Read | FileOpenFlags.Write)) == 0)
            throw new FileSystemException(FileSystemError.Failure, $"Open for neither reading nor writing: {path}");

        // The permissions of a new file are ignored: the storage has none (no SetPermissions capability).
        return await S3Errors.RunAsync<IFileHandle>(path, async () =>
        {
            var key = _keys.FileKey(normalized);
            var existing = await _store.HeadAsync(key, ct).ConfigureAwait(false);
            if (existing == null)
            {
                if (await IsDirectoryAsync(normalized, ct).ConfigureAwait(false))
                    throw new FileSystemException(FileSystemError.IsADirectory, $"Is a directory: {path}");
                if ((flags & FileOpenFlags.Create) == 0)
                    throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");
                await RequireParentDirectoryAsync(normalized, path, ct).ConfigureAwait(false);
            }
            else if ((flags & (FileOpenFlags.Create | FileOpenFlags.Exclusive)) == (FileOpenFlags.Create | FileOpenFlags.Exclusive))
            {
                throw new FileSystemException(FileSystemError.AlreadyExists, $"Already exists: {path}");
            }

            var keep = (flags & FileOpenFlags.Truncate) == 0 ? existing : null;
            var handle = new S3FileHandle(_store, key, normalized, flags, keep);
            await handle.PrefetchAsync(ct).ConfigureAwait(false);
            return handle;
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask CreateDirectoryAsync(string path, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        await S3Errors.RunAsync(path, async () =>
        {
            if (await StatCoreAsync(normalized, ct).ConfigureAwait(false) != null)
                throw new FileSystemException(FileSystemError.AlreadyExists, $"Already exists: {path}");
            await RequireParentDirectoryAsync(normalized, path, ct).ConfigureAwait(false);
            await _store.PutAsync(_keys.DirectoryPrefix(normalized), [], 0, ct).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask DeleteFileAsync(string path, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        if (normalized == VirtualPath.Root)
            throw new FileSystemException(FileSystemError.IsADirectory, $"Is a directory: {path}");
        await S3Errors.RunAsync(path, async () =>
        {
            var key = _keys.FileKey(normalized);
            if (await _store.HeadAsync(key, ct).ConfigureAwait(false) == null)
            {
                throw await IsDirectoryAsync(normalized, ct).ConfigureAwait(false)
                    ? new FileSystemException(FileSystemError.IsADirectory, $"Is a directory: {path}")
                    : new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");
            }
            await _store.DeleteAsync(key, ct).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask DeleteDirectoryAsync(string path, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        if (normalized == VirtualPath.Root)
            throw new FileSystemException(FileSystemError.PermissionDenied, "The user root directory cannot be removed.");
        await S3Errors.RunAsync(path, async () =>
        {
            var prefix = _keys.DirectoryPrefix(normalized);
            var objects = await _store.FirstObjectsAsync(prefix, 2, ct).ConfigureAwait(false);
            if (objects.Count == 0)
            {
                throw await _store.HeadAsync(_keys.FileKey(normalized), ct).ConfigureAwait(false) != null
                    ? new FileSystemException(FileSystemError.NotADirectory, $"Not a directory: {path}")
                    : new FileSystemException(FileSystemError.NoSuchFile, $"No such directory: {path}");
            }
            if (objects.Any(o => o.Key != prefix))
                throw new FileSystemException(FileSystemError.DirectoryNotEmpty, $"The directory is not empty: {path}");
            await _store.DeleteAsync(prefix, ct).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var source = VirtualPath.Normalize(oldPath);
        var target = VirtualPath.Normalize(newPath);
        if (source == VirtualPath.Root || target == VirtualPath.Root)
            throw new FileSystemException(FileSystemError.PermissionDenied, "The user root directory cannot be moved or replaced.");

        await S3Errors.RunAsync(oldPath, async () =>
        {
            var sourceKey = _keys.FileKey(source);
            var sourceFile = await _store.HeadAsync(sourceKey, ct).ConfigureAwait(false);
            if (sourceFile == null && !await IsDirectoryAsync(source, ct).ConfigureAwait(false))
                throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {oldPath}");
            await RequireParentDirectoryAsync(target, newPath, ct).ConfigureAwait(false);
            if (source == target)
                return; // rename(2) of a path to itself does nothing

            if (await StatCoreAsync(target, ct).ConfigureAwait(false) is { } existing)
            {
                if ((flags & RenameFlags.ReplaceExisting) == 0 || sourceFile == null)
                    throw new FileSystemException(FileSystemError.AlreadyExists, $"The target already exists: {newPath}");
                if (existing.IsDirectory)
                    throw new FileSystemException(FileSystemError.IsADirectory, $"The target is a directory: {newPath}");
            }

            if (sourceFile != null)
            {
                await _store.CopyAsync(sourceKey, _keys.FileKey(target), sourceFile, ct).ConfigureAwait(false);
                await _store.DeleteAsync(sourceKey, ct).ConfigureAwait(false);
                return;
            }

            if (target.StartsWith(source + "/", StringComparison.Ordinal))
                throw new FileSystemException(FileSystemError.Failure, $"A directory cannot be moved into itself: {newPath}");
            await RenameDirectoryAsync(_keys.DirectoryPrefix(source), _keys.DirectoryPrefix(target), ct).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);
    }

    /// <summary>Copies every object below the source prefix, then removes the sources: a failure leaves the sources complete.</summary>
    private async Task RenameDirectoryAsync(string sourcePrefix, string targetPrefix, CancellationToken ct)
    {
        var copied = new List<string>();
        await foreach (var item in _store.ListAllAsync(sourcePrefix, ct).ConfigureAwait(false))
        {
            var info = new S3ObjectInfo(item.Size ?? 0, S3ObjectStore.ToUtc(item.LastModified), item.ETag);
            await _store.CopyAsync(item.Key, targetPrefix + item.Key.Substring(sourcePrefix.Length), info, ct).ConfigureAwait(false);
            copied.Add(item.Key);
        }
        await _store.DeleteManyAsync(copied, ct).ConfigureAwait(false);
    }

    public async ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        await S3Errors.RunAsync(path, async () =>
        {
            var entry = await StatCoreAsync(normalized, ct).ConfigureAwait(false)
                ?? throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");
            if (update.Size != null && entry.IsDirectory)
                throw new FileSystemException(FileSystemError.IsADirectory, $"Is a directory: {path}");
            RequireNoChange(update, entry.Size, path);
        }, ct).ConfigureAwait(false);
    }

    /// <summary>The storage has no size changes, permissions or times: an update that changes one of them is not supported.</summary>
    internal static void RequireNoChange(FileAttributesUpdate update, long currentSize, string path)
    {
        if (update.Size is { } size && size != currentSize)
            throw new FileSystemException(FileSystemError.OpNotSupported, $"The storage cannot change the size of a file: {path}");
        if (update.Permissions != null)
            throw new FileSystemException(FileSystemError.OpNotSupported, $"The storage has no permissions: {path}");
        if (update.HasTimes)
            throw new FileSystemException(FileSystemError.OpNotSupported, $"The storage cannot set the times: {path}");
    }

    /// <summary>An object store has no size; the space is unknown (null) for every existing path.</summary>
    public async ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        return await S3Errors.RunAsync(path, async () =>
        {
            _ = await StatCoreAsync(normalized, ct).ConfigureAwait(false) ?? throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");
            return (StorageSpace?)null;
        }, ct).ConfigureAwait(false);
    }

    /// <summary>The file (HeadObject) or else the directory (an object below its prefix) at a normalized path.</summary>
    private async Task<FileSystemEntry?> StatCoreAsync(string normalized, CancellationToken ct)
    {
        if (normalized == VirtualPath.Root)
            return RootEntry;
        var name = VirtualPath.GetName(normalized);
        if (await _store.HeadAsync(_keys.FileKey(normalized), ct).ConfigureAwait(false) is { } file)
            return File(name, file);

        var prefix = _keys.DirectoryPrefix(normalized);
        var first = (await _store.FirstObjectsAsync(prefix, 1, ct).ConfigureAwait(false)).FirstOrDefault();
        if (first == null)
            return null;
        // The marker "dir/" is the first key below the prefix when it exists.
        return Directory(name, first.Key == prefix ? S3ObjectStore.ToUtc(first.LastModified) : DateTime.UnixEpoch);
    }

    private async Task<bool> IsDirectoryAsync(string normalized, CancellationToken ct)
        => normalized == VirtualPath.Root || (await _store.FirstObjectsAsync(_keys.DirectoryPrefix(normalized), 1, ct).ConfigureAwait(false)).Count > 0;

    /// <summary>The parent of a new entry must be a directory (a missing parent and a file are both NoSuchFile, like ENOENT and ENOTDIR).</summary>
    private async Task RequireParentDirectoryAsync(string normalized, string path, CancellationToken ct)
    {
        if (!await IsDirectoryAsync(VirtualPath.GetParent(normalized), ct).ConfigureAwait(false))
            throw new FileSystemException(FileSystemError.NoSuchFile, $"No such directory: {path}/..");
    }

    private static FileSystemEntry File(string name, S3ObjectInfo info)
        => new(name, FileSystemEntryType.File, info.Size, info.LastModifiedUtc, info.LastModifiedUtc);

    private static FileSystemEntry Directory(string name, DateTime lastWriteUtc)
        => new(name, FileSystemEntryType.Directory, 0, lastWriteUtc, lastWriteUtc);
}
