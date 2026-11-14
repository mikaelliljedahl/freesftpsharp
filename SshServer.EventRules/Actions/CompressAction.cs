using System.IO.Compression;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Storage;

namespace SshServer.EventRules.Actions;

/// <summary>
/// Puts files and directories of the user into a zip archive in the storage of the user. The archive is built in a
/// temporary file of the server and then written to the storage, so it works on every backend.
/// </summary>
public sealed class CompressAction : UserFileAction
{
    public const string ArchiveKey = "Archive";

    public CompressAction(UserFileSystems fileSystems) : base(fileSystems)
    {
    }

    public override string Type => "Compress";

    public override string DisplayName => "Compress to zip";

    public override string Description => "Writes files and directories of the user into a zip archive.";

    public override IReadOnlyList<EventActionField> Fields { get; } =
    [
        PathsField("Files and directories"),
        new(ArchiveKey, "Archive", EventActionFieldKind.Text) { Help = "For example /archive/{{Name}}.zip.", Placeholders = true },
        new(OverwriteKey, "Replace an existing archive", EventActionFieldKind.Boolean),
    ];

    public override IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options) => Required(options, (ArchiveKey, "archive"));

    protected override async Task<EventActionResult> ExecuteAsync(EventActionContext context, IFileSystem fileSystem, CancellationToken ct)
    {
        var archive = SinglePath(context, ArchiveKey);
        var paths = Paths(context);
        if (archive == null || paths.Count == 0)
            return EventActionResult.Failed("The archive or the paths are empty.");
        if (paths.Contains(archive))
            return EventActionResult.Failed("The archive cannot be one of its own files.");

        var temporary = Path.Combine(Path.GetTempPath(), "freesftpsharp-zip-" + Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            var files = 0;
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 81920, FileOptions.Asynchronous))
            {
                using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
                {
                    foreach (var path in paths)
                    {
                        var entry = await fileSystem.StatAsync(path, followLinks: true, ct)
                            ?? throw new FileSystemException(FileSystemError.NoSuchFile, $"{path} does not exist.");
                        files += await AddAsync(zip, fileSystem, path, entry, VirtualPath.GetName(path), ct);
                    }
                }

                await FileOperations.EnsureDirectoryAsync(fileSystem, VirtualPath.GetParent(archive), ct);
                stream.Position = 0;
                var flags = FileOpenFlags.Write | FileOpenFlags.Create | (context.BoolOption(OverwriteKey) ? FileOpenFlags.Truncate : FileOpenFlags.Exclusive);
                var output = await fileSystem.OpenAsync(archive, flags, null, ct);
                try
                {
                    var buffer = new byte[81920];
                    long offset = 0;
                    int read;
                    while ((read = await stream.ReadAsync(buffer, ct)) > 0)
                    {
                        await output.WriteAsync(offset, buffer.AsMemory(0, read), ct);
                        offset += read;
                    }
                }
                catch
                {
                    await output.AbortAsync();
                    throw;
                }
                await output.DisposeAsync();
            }
            return EventActionResult.Ok($"Wrote {archive} with {files} files.");
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    private static async Task<int> AddAsync(ZipArchive zip, IFileSystem fileSystem, string path, FileSystemEntry entry, string entryName, CancellationToken ct)
    {
        if (entry.Type == FileSystemEntryType.Symlink)
            return 0;
        if (entry.IsDirectory)
        {
            zip.CreateEntry(entryName + "/");
            var files = 0;
            await foreach (var child in fileSystem.ListAsync(path, ct))
                files += await AddAsync(zip, fileSystem, VirtualPath.Combine(path, child.Name), child, entryName + "/" + child.Name, ct);
            return files;
        }

        var zipEntry = zip.CreateEntry(entryName, CompressionLevel.Optimal);
        zipEntry.LastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(entry.LastWriteTimeUtc, DateTimeKind.Utc));
        await using var target = zipEntry.Open();
        await using var handle = await fileSystem.OpenAsync(path, FileOpenFlags.Read, null, ct);
        var buffer = new byte[81920];
        long offset = 0;
        int read;
        while ((read = await handle.ReadAsync(offset, buffer, ct)) > 0)
        {
            await target.WriteAsync(buffer.AsMemory(0, read), ct);
            offset += read;
        }
        return 1;
    }
}
