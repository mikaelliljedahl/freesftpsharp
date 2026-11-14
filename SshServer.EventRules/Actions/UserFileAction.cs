using SshServer.Interfaces;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Storage;

namespace SshServer.EventRules.Actions;

/// <summary>
/// The file system of a user for the actions: through <see cref="IFileSystemFactory"/>, so the actions work on every
/// storage backend and their operations give events (with the protocol <see cref="EventRuleRunner.Protocol"/>). The
/// per-path permissions of the user are not applied: the rule is the decision of an administrator.
/// </summary>
public sealed class UserFileSystems
{
    private readonly IFileSystemFactory _factory;

    public UserFileSystems(IFileSystemFactory factory)
    {
        _factory = factory;
    }

    public ValueTask<IFileSystem> OpenAsync(User user, CancellationToken ct)
        => _factory.CreateAsync(user, new ClientContext(EventRuleRunner.Protocol, null) { SkipPermissions = true }, ct);
}

/// <summary>The base of the actions on the files of the user of the run.</summary>
public abstract class UserFileAction : IEventRuleAction
{
    public const string PathsKey = "Paths";
    public const string SourceKey = "Source";
    public const string TargetKey = "Target";
    public const string OverwriteKey = "Overwrite";

    private readonly UserFileSystems _fileSystems;

    protected UserFileAction(UserFileSystems fileSystems)
    {
        _fileSystems = fileSystems;
    }

    public abstract string Type { get; }

    public abstract string DisplayName { get; }

    public abstract string Description { get; }

    public bool NeedsUser => true;

    public abstract IReadOnlyList<EventActionField> Fields { get; }

    public abstract IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options);

    public async Task<EventActionResult> ExecuteAsync(EventActionContext context, CancellationToken ct)
    {
        var fileSystem = await _fileSystems.OpenAsync(context.User!, ct);
        return await ExecuteAsync(context, fileSystem, ct);
    }

    protected abstract Task<EventActionResult> ExecuteAsync(EventActionContext context, IFileSystem fileSystem, CancellationToken ct);

    /// <summary>The field of the paths, one per line, with <paramref name="defaultValue"/> for a new action.</summary>
    protected static EventActionField PathsField(string label, string? defaultValue = "{{VirtualPath}}") => new(PathsKey, label, EventActionFieldKind.MultilineText)
    {
        Help = "One virtual path per line, for example /processed/{{Name}}.",
        DefaultValue = defaultValue,
        Placeholders = true,
    };

    protected static IReadOnlyList<string> Required(IReadOnlyDictionary<string, string> options, params (string Key, string Label)[] fields)
        => fields.Where(f => !options.TryGetValue(f.Key, out var v) || string.IsNullOrWhiteSpace(v)).Select(f => $"Enter the {f.Label}.").ToArray();

    /// <summary>The rendered, normalized paths of a multi-line option.</summary>
    protected static IReadOnlyList<string> Paths(EventActionContext context, string key = PathsKey, string fallback = "{{VirtualPath}}")
        => context.Option(key, fallback).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => context.Render(line).Trim())
            .Where(path => path.Length > 0)
            .Select(VirtualPath.Normalize)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

    /// <summary>The rendered, normalized path of an option; null when it renders to nothing.</summary>
    protected static string? SinglePath(EventActionContext context, string key, string fallback = "")
    {
        var rendered = context.RenderOption(key, fallback).Trim();
        return rendered.Length == 0 ? null : VirtualPath.Normalize(rendered);
    }
}

/// <summary>File operations of the actions over <see cref="IFileSystem"/>, for every backend.</summary>
public static class FileOperations
{
    private const int BufferSize = 81920;

    /// <summary>Creates the directory and its missing parents.</summary>
    public static async ValueTask EnsureDirectoryAsync(IFileSystem fileSystem, string directory, CancellationToken ct)
    {
        if (directory == VirtualPath.Root)
            return;
        var entry = await fileSystem.StatAsync(directory, followLinks: true, ct);
        if (entry != null)
        {
            if (!entry.IsDirectory)
                throw new FileSystemException(FileSystemError.NotADirectory, $"{directory} is a file, not a directory.");
            return;
        }
        await EnsureDirectoryAsync(fileSystem, VirtualPath.GetParent(directory), ct);
        try
        {
            await fileSystem.CreateDirectoryAsync(directory, ct);
        }
        catch (FileSystemException ex) when (ex.Error == FileSystemError.AlreadyExists)
        {
            // Created at the same time.
        }
    }

    /// <summary>Copies a file or a directory tree; returns the number of files.</summary>
    public static async ValueTask<int> CopyAsync(IFileSystem fileSystem, string source, string target, bool overwrite, CancellationToken ct)
    {
        var entry = await fileSystem.StatAsync(source, followLinks: true, ct)
            ?? throw new FileSystemException(FileSystemError.NoSuchFile, $"{source} does not exist.");
        if (target == source || target.StartsWith(source + "/", StringComparison.Ordinal))
            throw new FileSystemException(FileSystemError.Failure, $"{source} cannot be copied into itself.");
        if (!entry.IsDirectory)
        {
            await CopyFileAsync(fileSystem, source, target, overwrite, ct);
            return 1;
        }

        await EnsureDirectoryAsync(fileSystem, target, ct);
        var files = 0;
        await foreach (var child in fileSystem.ListAsync(source, ct))
            files += await CopyAsync(fileSystem, VirtualPath.Combine(source, child.Name), VirtualPath.Combine(target, child.Name), overwrite, ct);
        return files;
    }

    /// <summary>Copies one file; the parent of the target is created when it is missing.</summary>
    public static async ValueTask CopyFileAsync(IFileSystem fileSystem, string source, string target, bool overwrite, CancellationToken ct)
    {
        await EnsureDirectoryAsync(fileSystem, VirtualPath.GetParent(target), ct);
        await using var input = await fileSystem.OpenAsync(source, FileOpenFlags.Read, null, ct);
        var flags = FileOpenFlags.Write | FileOpenFlags.Create | (overwrite ? FileOpenFlags.Truncate : FileOpenFlags.Exclusive);
        var output = await fileSystem.OpenAsync(target, flags, null, ct);
        try
        {
            var buffer = new byte[BufferSize];
            long offset = 0;
            int read;
            while ((read = await input.ReadAsync(offset, buffer, ct)) > 0)
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

    /// <summary>Removes a file, or a directory (with <paramref name="recursive"/> also its content); returns the number of files.</summary>
    public static async ValueTask<int> DeleteAsync(IFileSystem fileSystem, string path, bool recursive, CancellationToken ct)
    {
        var entry = await fileSystem.StatAsync(path, followLinks: false, ct)
            ?? throw new FileSystemException(FileSystemError.NoSuchFile, $"{path} does not exist.");
        if (!entry.IsDirectory)
        {
            await fileSystem.DeleteFileAsync(path, ct);
            return 1;
        }

        var files = 0;
        if (recursive)
        {
            var children = new List<FileSystemEntry>();
            await foreach (var child in fileSystem.ListAsync(path, ct))
                children.Add(child);
            foreach (var child in children)
                files += await DeleteAsync(fileSystem, VirtualPath.Combine(path, child.Name), recursive: true, ct);
        }
        await fileSystem.DeleteDirectoryAsync(path, ct);
        return files;
    }

    /// <summary>Reads a file into memory; null when it is larger than <paramref name="maxBytes"/>.</summary>
    public static async ValueTask<byte[]?> ReadAllAsync(IFileSystem fileSystem, string path, long maxBytes, CancellationToken ct)
    {
        await using var handle = await fileSystem.OpenAsync(path, FileOpenFlags.Read, null, ct);
        var size = (await handle.StatAsync(ct)).Size;
        if (size > maxBytes)
            return null;
        using var memory = new MemoryStream((int)Math.Max(size, 0));
        var buffer = new byte[BufferSize];
        long offset = 0;
        int read;
        while ((read = await handle.ReadAsync(offset, buffer, ct)) > 0)
        {
            if (offset + read > maxBytes)
                return null;
            memory.Write(buffer, 0, read);
            offset += read;
        }
        return memory.ToArray();
    }
}
