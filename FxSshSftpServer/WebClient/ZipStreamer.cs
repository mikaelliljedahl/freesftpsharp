using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Storage;

namespace FxSshSftpServer.WebClient
{
    /// <summary>One entry of a zip download: the virtual path and the name in the archive.</summary>
    public sealed record ZipItem(string Path, string EntryName, bool IsDirectory, DateTime LastWriteTimeUtc);

    /// <summary>
    /// "Download as zip" of the web client (#69): the selected files and folders (with everything below them) as one
    /// zip archive, written straight to the response. The archive is made with the asynchronous <see cref="ZipArchive"/>
    /// in create mode (it needs no seekable stream) and each file is read in blocks through the storage decorator chain,
    /// so there is no temporary file and no file is held in memory.
    /// </summary>
    public static class ZipStreamer
    {
        private const int BlockSize = 128 * 1024;

        /// <summary>The most entries of one archive.</summary>
        public const int MaxEntries = 100_000;

        /// <summary>
        /// The entries of the selection: a file under its name, a folder with all entries below it (an empty folder as a
        /// folder entry). Throws <see cref="FileSystemException"/> when a path does not exist or cannot be listed, and
        /// <see cref="InvalidOperationException"/> above <see cref="MaxEntries"/>.
        /// </summary>
        public static async Task<IReadOnlyList<ZipItem>> CollectAsync(IFileSystem fileSystem, IEnumerable<string> paths, CancellationToken ct)
        {
            var items = new List<ZipItem>();
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var raw in paths)
            {
                var path = VirtualPath.Normalize(raw);
                if (path == VirtualPath.Root)
                    throw new FileSystemException(FileSystemError.InvalidPath, "Select files or folders, not the root.");
                var entry = await fileSystem.StatAsync(path, true, ct)
                            ?? throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");
                var name = VirtualPath.GetName(path);
                if (!names.Add(name))
                    continue; // the same entry twice
                if (entry.IsDirectory)
                    await AddDirectoryAsync(fileSystem, path, name, entry.LastWriteTimeUtc, items, ct);
                else
                    Add(items, new ZipItem(path, name, false, entry.LastWriteTimeUtc));
            }
            return items;
        }

        /// <summary>
        /// Writes the archive. A file that cannot be read any more (removed, or refused by a rule after the check) is left
        /// out and logged: the response has started, so the status code cannot tell it.
        /// </summary>
        public static async Task WriteAsync(IFileSystem fileSystem, IReadOnlyList<ZipItem> items, Stream output, ILogger logger, CancellationToken ct)
        {
            await using var stream = new PendingWriteStream(output);
            var buffer = ArrayPool<byte>.Shared.Rent(BlockSize);
            try
            {
                await WriteEntriesAsync(fileSystem, items, stream, buffer, logger, ct);
                await stream.SendPendingAsync(ct);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private static async Task WriteEntriesAsync(IFileSystem fileSystem, IReadOnlyList<ZipItem> items, PendingWriteStream stream, byte[] buffer,
            ILogger logger, CancellationToken ct)
        {
            await using var archive = await ZipArchive.CreateAsync(stream, ZipArchiveMode.Create, leaveOpen: true, entryNameEncoding: null, ct);
            foreach (var item in items)
            {
                if (item.IsDirectory)
                {
                    var folder = archive.CreateEntry(item.EntryName + "/", CompressionLevel.NoCompression);
                    folder.LastWriteTime = ZipTime(item.LastWriteTimeUtc);
                    continue;
                }

                IFileHandle handle;
                try
                {
                    handle = await fileSystem.OpenAsync(item.Path, FileOpenFlags.Read, null, ct);
                }
                catch (FileSystemException ex)
                {
                    logger.LogWarning("The zip download left out {Path}: {Reason}", LogText.Clean(item.Path), LogText.Clean(ex.Message));
                    continue;
                }

                await using (handle)
                {
                    var entry = archive.CreateEntry(item.EntryName, CompressionLevel.Fastest);
                    entry.LastWriteTime = ZipTime(item.LastWriteTimeUtc);
                    await using var target = await entry.OpenAsync(ct);
                    long offset = 0;
                    while (true)
                    {
                        var read = await handle.ReadAsync(offset, buffer.AsMemory(0, BlockSize), ct);
                        if (read == 0)
                            break;
                        await target.WriteAsync(buffer.AsMemory(0, read), ct);
                        offset += read;
                    }
                }
                // The records that the archive wrote synchronously for this entry.
                await stream.SendPendingAsync(ct);
            }
        }

        private static async Task AddDirectoryAsync(IFileSystem fileSystem, string path, string entryName, DateTime lastWrite,
            List<ZipItem> items, CancellationToken ct)
        {
            var children = new List<FileSystemEntry>();
            await foreach (var child in fileSystem.ListAsync(path, ct))
                children.Add(child);
            if (children.Count == 0)
            {
                Add(items, new ZipItem(path, entryName, true, lastWrite));
                return;
            }
            children.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));
            foreach (var child in children)
            {
                var childPath = VirtualPath.Combine(path, child.Name);
                var childName = entryName + "/" + child.Name;
                if (child.IsDirectory)
                    await AddDirectoryAsync(fileSystem, childPath, childName, child.LastWriteTimeUtc, items, ct);
                else if (child.Type == FileSystemEntryType.File)
                    Add(items, new ZipItem(childPath, childName, false, child.LastWriteTimeUtc));
                // A link is left out: following it could leave the folder or loop.
            }
        }

        private static void Add(List<ZipItem> items, ZipItem item)
        {
            if (items.Count >= MaxEntries)
                throw new InvalidOperationException($"The selection has more than {MaxEntries} entries. Select fewer files.");
            items.Add(item);
        }

        // A zip archive stores the years 1980 to 2107.
        private static DateTimeOffset ZipTime(DateTime utc)
        {
            var value = DateTime.SpecifyKind(utc, DateTimeKind.Utc);
            if (value.Year < 1980)
                return new DateTimeOffset(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);
            if (value.Year > 2107)
                return new DateTimeOffset(2107, 12, 31, 0, 0, 0, TimeSpan.Zero);
            return new DateTimeOffset(value);
        }
    }
}
