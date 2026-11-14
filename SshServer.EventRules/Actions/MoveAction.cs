using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Storage;

namespace SshServer.EventRules.Actions;

/// <summary>Moves (renames) a file or directory of the user; the parent of the target is created. A backend without rename copies and deletes a file.</summary>
public sealed class MoveAction : UserFileAction
{
    public MoveAction(UserFileSystems fileSystems) : base(fileSystems)
    {
    }

    public override string Type => "Move";

    public override string DisplayName => "Move or rename";

    public override string Description => "Moves a file or directory of the user to another path.";

    public override IReadOnlyList<EventActionField> Fields { get; } =
    [
        new(SourceKey, "Source", EventActionFieldKind.Text) { DefaultValue = "{{VirtualPath}}", Placeholders = true },
        new(TargetKey, "Target", EventActionFieldKind.Text) { Help = "For example /processed/{{Name}}.", Placeholders = true },
        new(OverwriteKey, "Replace an existing file at the target", EventActionFieldKind.Boolean),
    ];

    public override IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options) => Required(options, (TargetKey, "target"));

    protected override async Task<EventActionResult> ExecuteAsync(EventActionContext context, IFileSystem fileSystem, CancellationToken ct)
    {
        var source = SinglePath(context, SourceKey, "{{VirtualPath}}");
        var target = SinglePath(context, TargetKey);
        if (source == null || target == null)
            return EventActionResult.Failed("The source or the target is empty.");
        var overwrite = context.BoolOption(OverwriteKey);

        await FileOperations.EnsureDirectoryAsync(fileSystem, VirtualPath.GetParent(target), ct);
        if (fileSystem.Capabilities.HasFlag(StorageCapabilities.Rename))
        {
            await fileSystem.RenameAsync(source, target, overwrite ? RenameFlags.ReplaceExisting : RenameFlags.None, ct);
        }
        else
        {
            var entry = await fileSystem.StatAsync(source, followLinks: true, ct)
                ?? throw new FileSystemException(FileSystemError.NoSuchFile, $"{source} does not exist.");
            if (entry.IsDirectory)
                return EventActionResult.Failed("This storage cannot rename, and a directory is not moved by copying.");
            await FileOperations.CopyFileAsync(fileSystem, source, target, overwrite, ct);
            await fileSystem.DeleteFileAsync(source, ct);
        }
        return EventActionResult.Ok($"Moved {source} to {target}.");
    }
}
