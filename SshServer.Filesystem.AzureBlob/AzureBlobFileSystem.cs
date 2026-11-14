using System.Runtime.CompilerServices;
using Azure.Storage.Blobs;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.AzureBlob;

/// <summary>
/// One user's storage in an Azure Blob container (or below a name prefix in it).
/// <para>
/// Directories are virtual: a directory exists when a blob name starts with its prefix ("dir/"). A new directory is a
/// zero-length marker blob "dir/" with the metadata hdi_isfolder=true (as Storage Explorer and Data Lake write it), so an
/// empty directory stays; removing the last file of a directory without a marker (one that another tool wrote) makes
/// the directory disappear. Listings use the hierarchy listing with the delimiter "/", page by page, and the blob
/// prefixes are the directories. A directory has the time of its marker, or 1970-01-01 (also in a listing, which has no
/// time for a blob prefix).
/// </para>
/// <para>
/// Files: reads are ranged downloads through a read-ahead buffer (<see cref="AzureBlobReadBuffer"/>); writes are
/// sequential, streamed as block blob blocks (<see cref="AzureBlobUpload"/>), and the blob appears when the file is
/// closed (Put Block List), so an upload that is given up leaves nothing visible. A rename is a copy on the server and a
/// delete (for a directory: of every blob below it), not atomic. There are no POSIX permissions, no settable times and
/// no links; <see cref="StorageCapabilities"/> says so, and those changes throw <see cref="FileSystemError.OpNotSupported"/>.
/// A change that changes nothing (an empty update, the current size) works.
/// </para>
/// </summary>
public sealed class AzureBlobFileSystem : IFileSystem
{
    private static readonly FileSystemEntry RootEntry = Directory(VirtualPath.Root, DateTime.UnixEpoch);

    private readonly AzureBlobStore _store;
    private readonly AzureBlobNameMapper _names;

    public AzureBlobFileSystem(BlobContainerClient container, AzureBlobStorageOptions options)
        : this(new AzureBlobStore(container, options))
    {
    }

    internal AzureBlobFileSystem(AzureBlobStore store)
    {
        _store = store;
        _names = new AzureBlobNameMapper(store.Options.KeyPrefix);
    }

    /// <summary>
    /// Sequential writes, also at the end of an existing file (a resumed upload or an append),
    /// rename (by copy and delete) and the copy on the server.
    /// </summary>
    public StorageCapabilities Capabilities => StorageCapabilities.Append | StorageCapabilities.Rename | StorageCapabilities.ServerSideCopy;

    public async ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        return await AzureBlobErrors.RunAsync(path, () => StatCoreAsync(normalized, ct), ct).ConfigureAwait(false);
    }

    public async IAsyncEnumerable<FileSystemEntry> ListAsync(string path, [EnumeratorCancellation] CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        var prefix = _names.DirectoryPrefix(normalized);
        var found = false;
        var directories = new HashSet<string>(StringComparer.Ordinal); // a marker "dir" and the prefix "dir/" are one directory
        await using var items = _store.ListHierarchy(prefix, ct).GetAsyncEnumerator(ct);
        while (true)
        {
            bool has;
            try
            {
                has = await items.MoveNextAsync().ConfigureAwait(false);
            }
            catch (Exception ex) when (AzureBlobErrors.Translate(ex, path, ct) is { } translated)
            {
                throw translated;
            }
            if (!has)
                break;
            found = true;

            var item = items.Current;
            if (item.IsPrefix)
            {
                if (AzureBlobNameMapper.ChildName(prefix, item.Prefix) is { } directory && directories.Add(directory))
                    yield return Directory(directory, DateTime.UnixEpoch);
            }
            else if (!item.Blob.Name.EndsWith('/') && AzureBlobNameMapper.ChildName(prefix, item.Blob.Name) is { } name)
            {
                var properties = item.Blob.Properties;
                if (AzureBlobStore.IsFolder(item.Blob.Metadata))
                {
                    if (directories.Add(name))
                        yield return Directory(name, AzureBlobStore.ToUtc(properties.LastModified));
                }
                else
                {
                    yield return File(name, new BlobInfo(properties.ContentLength ?? 0, AzureBlobStore.ToUtc(properties.LastModified), properties.ETag ?? default));
                }
            }
        }

        if (!found && normalized != VirtualPath.Root)
        {
            // An empty directory has only its marker, which is not below its own prefix.
            var entry = await AzureBlobErrors.RunAsync(path, () => StatCoreAsync(normalized, ct), ct).ConfigureAwait(false);
            if (entry is not { IsDirectory: true })
            {
                throw entry != null
                    ? new FileSystemException(FileSystemError.NotADirectory, $"Not a directory: {path}")
                    : new FileSystemException(FileSystemError.NoSuchFile, $"No such directory: {path}");
            }
        }
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
        return await AzureBlobErrors.RunAsync<IFileHandle>(path, async () =>
        {
            var key = _names.FileName(normalized);
            var existing = await HeadFileAsync(key, ct).ConfigureAwait(false);
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
            var handle = new AzureBlobFileHandle(_store, key, normalized, flags, keep);
            await handle.PrefetchAsync(ct).ConfigureAwait(false);
            return handle;
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask CreateDirectoryAsync(string path, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        await AzureBlobErrors.RunAsync(path, async () =>
        {
            if (await StatCoreAsync(normalized, ct).ConfigureAwait(false) != null)
                throw new FileSystemException(FileSystemError.AlreadyExists, $"Already exists: {path}");
            await RequireParentDirectoryAsync(normalized, path, ct).ConfigureAwait(false);
            await _store.PutAsync(_names.MarkerName(normalized), [], 0, folderMarker: true, ct).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask DeleteFileAsync(string path, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        if (normalized == VirtualPath.Root)
            throw new FileSystemException(FileSystemError.IsADirectory, $"Is a directory: {path}");
        await AzureBlobErrors.RunAsync(path, async () =>
        {
            var key = _names.FileName(normalized);
            if (await HeadFileAsync(key, ct).ConfigureAwait(false) == null)
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
        await AzureBlobErrors.RunAsync(path, async () =>
        {
            if ((await _store.FirstBlobsAsync(_names.DirectoryPrefix(normalized), 1, ct).ConfigureAwait(false)).Count > 0)
                throw new FileSystemException(FileSystemError.DirectoryNotEmpty, $"The directory is not empty: {path}");
            var marker = _names.MarkerName(normalized);
            var existing = await _store.HeadAsync(marker, ct).ConfigureAwait(false);
            if (existing == null)
                throw new FileSystemException(FileSystemError.NoSuchFile, $"No such directory: {path}");
            if (!existing.IsFolder)
                throw new FileSystemException(FileSystemError.NotADirectory, $"Not a directory: {path}");
            await _store.DeleteAsync(marker, ct).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var source = VirtualPath.Normalize(oldPath);
        var target = VirtualPath.Normalize(newPath);
        if (source == VirtualPath.Root || target == VirtualPath.Root)
            throw new FileSystemException(FileSystemError.PermissionDenied, "The user root directory cannot be moved or replaced.");

        await AzureBlobErrors.RunAsync(oldPath, async () =>
        {
            var sourceKey = _names.FileName(source);
            var sourceFile = await HeadFileAsync(sourceKey, ct).ConfigureAwait(false);
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
                await _store.CopyAsync(sourceKey, _names.FileName(target), sourceFile, ct).ConfigureAwait(false);
                await _store.DeleteAsync(sourceKey, ct).ConfigureAwait(false);
                return;
            }

            if (target.StartsWith(source + "/", StringComparison.Ordinal))
                throw new FileSystemException(FileSystemError.Failure, $"A directory cannot be moved into itself: {newPath}");
            await RenameDirectoryAsync(_names.MarkerName(source), _names.MarkerName(target), _names.DirectoryPrefix(source), _names.DirectoryPrefix(target), ct).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);
    }

    /// <summary>Copies every blob below the source prefix, then removes the sources: a failure leaves the sources complete.</summary>
    private async Task RenameDirectoryAsync(string sourceMarker, string targetMarker, string sourcePrefix, string targetPrefix, CancellationToken ct)
    {
        var copied = new List<string>();
        var marker = await _store.HeadAsync(sourceMarker, ct).ConfigureAwait(false);
        if (marker is { IsFolder: true })
        {
            await _store.CopyAsync(sourceMarker, targetMarker, marker, ct).ConfigureAwait(false);
            copied.Add(sourceMarker);
        }
        await foreach (var item in _store.ListAll(sourcePrefix, ct).ConfigureAwait(false))
        {
            var info = new BlobInfo(item.Properties.ContentLength ?? 0, AzureBlobStore.ToUtc(item.Properties.LastModified), item.Properties.ETag ?? default);
            await _store.CopyAsync(item.Name, targetPrefix + item.Name.Substring(sourcePrefix.Length), info, ct).ConfigureAwait(false);
            copied.Add(item.Name);
        }
        foreach (var name in copied)
            await _store.DeleteAsync(name, ct).ConfigureAwait(false);
    }

    public async ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = VirtualPath.Normalize(path);
        await AzureBlobErrors.RunAsync(path, async () =>
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
        return await AzureBlobErrors.RunAsync(path, async () =>
        {
            _ = await StatCoreAsync(normalized, ct).ConfigureAwait(false) ?? throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");
            return (StorageSpace?)null;
        }, ct).ConfigureAwait(false);
    }

    /// <summary>The blob of the file, or null: a missing blob and a directory marker are not files.</summary>
    private async Task<BlobInfo?> HeadFileAsync(string name, CancellationToken ct)
        => await _store.HeadAsync(name, ct).ConfigureAwait(false) is { IsFolder: false } file ? file : null;

    /// <summary>
    /// The file or else the directory at a normalized path: a blob that is not a marker is a file; a marker blob, or any
    /// blob below the prefix "path/", makes a directory. The time of a directory is the one of its marker, or 1970-01-01.
    /// </summary>
    private async Task<FileSystemEntry?> StatCoreAsync(string normalized, CancellationToken ct)
    {
        if (normalized == VirtualPath.Root)
            return RootEntry;
        var name = VirtualPath.GetName(normalized);
        var blob = await _store.HeadAsync(_names.FileName(normalized), ct).ConfigureAwait(false);
        if (blob is { IsFolder: false })
            return File(name, blob);
        if (blob != null)
            return Directory(name, blob.LastModifiedUtc);
        var hasChildren = (await _store.FirstBlobsAsync(_names.DirectoryPrefix(normalized), 1, ct).ConfigureAwait(false)).Count > 0;
        return hasChildren ? Directory(name, DateTime.UnixEpoch) : null;
    }

    private async Task<bool> IsDirectoryAsync(string normalized, CancellationToken ct)
        => (await StatCoreAsync(normalized, ct).ConfigureAwait(false))?.IsDirectory == true;

    /// <summary>The parent of a new entry must be a directory (a missing parent and a file are both NoSuchFile, like ENOENT and ENOTDIR).</summary>
    private async Task RequireParentDirectoryAsync(string normalized, string path, CancellationToken ct)
    {
        if (!await IsDirectoryAsync(VirtualPath.GetParent(normalized), ct).ConfigureAwait(false))
            throw new FileSystemException(FileSystemError.NoSuchFile, $"No such directory: {path}/..");
    }

    private static FileSystemEntry File(string name, BlobInfo info)
        => new(name, FileSystemEntryType.File, info.Size, info.LastModifiedUtc, info.LastModifiedUtc);

    private static FileSystemEntry Directory(string name, DateTime lastWriteUtc)
        => new(name, FileSystemEntryType.Directory, 0, lastWriteUtc, lastWriteUtc);
}
