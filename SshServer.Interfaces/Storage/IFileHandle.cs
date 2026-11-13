namespace SshServer.Interfaces.Storage;

/// <summary>
/// An open file from <see cref="IFileSystem.OpenAsync"/>. All I/O is positional; the handle has no cursor. Failures
/// throw <see cref="FileSystemException"/>. <see cref="IAsyncDisposable.DisposeAsync"/> writes the buffered data and
/// closes the file; a failure of that last write is thrown, and the file is closed in all cases. A second dispose
/// does nothing.
/// </summary>
public interface IFileHandle : IAsyncDisposable
{
    /// <summary>
    /// Reads up to <paramref name="buffer"/>.Length bytes at <paramref name="offset"/>. Returns the number of bytes read;
    /// 0 at or past the end of the file. A handle without <see cref="FileOpenFlags.Read"/> throws
    /// <see cref="FileSystemError.PermissionDenied"/>.
    /// </summary>
    ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken ct);

    /// <summary>
    /// Writes <paramref name="data"/> at <paramref name="offset"/>; a write past the end extends the file (the gap is
    /// zeros). With <see cref="FileOpenFlags.Append"/> every write goes to the end. Without
    /// <see cref="StorageCapabilities.RandomAccessWrite"/> only a write at the current end of the file is accepted,
    /// others throw <see cref="FileSystemError.OpNotSupported"/>. A handle without <see cref="FileOpenFlags.Write"/>
    /// throws <see cref="FileSystemError.PermissionDenied"/>.
    /// </summary>
    ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct);

    /// <summary>Writes the buffered data to stable storage (SFTP fsync@openssh.com).</summary>
    ValueTask FlushAsync(CancellationToken ct);

    /// <summary>
    /// The attributes of the open file. The size includes the data that is not flushed yet. When the file was removed
    /// or replaced while it is open, the type is <see cref="FileSystemEntryType.File"/> and only the size is known.
    /// </summary>
    ValueTask<FileSystemEntry> StatAsync(CancellationToken ct);

    /// <summary>Changes the attributes of the open file (SFTP FSETSTAT), see <see cref="IFileSystem.SetAttributesAsync"/>.</summary>
    ValueTask SetAttributesAsync(FileAttributesUpdate update, CancellationToken ct);
}
