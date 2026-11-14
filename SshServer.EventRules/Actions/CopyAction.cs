using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Storage;

namespace SshServer.EventRules.Actions;

/// <summary>Copies a file or a directory tree of the user on the server; the parents of the target are created.</summary>
public sealed class CopyAction : UserFileAction
{
    public CopyAction(UserFileSystems fileSystems) : base(fileSystems)
    {
    }

    public override string Type => "Copy";

    public override string DisplayName => "Copy";

    public override string Description => "Copies a file or directory of the user to another path.";

    public override IReadOnlyList<EventActionField> Fields { get; } =
    [
        new(SourceKey, "Source", EventActionFieldKind.Text) { DefaultValue = "{{VirtualPath}}", Placeholders = true },
        new(TargetKey, "Target", EventActionFieldKind.Text) { Help = "For example /archive/{{Date}}/{{Name}}.", Placeholders = true },
        new(OverwriteKey, "Replace existing files at the target", EventActionFieldKind.Boolean),
    ];

    public override IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options) => Required(options, (TargetKey, "target"));

    protected override async Task<EventActionResult> ExecuteAsync(EventActionContext context, IFileSystem fileSystem, CancellationToken ct)
    {
        var source = SinglePath(context, SourceKey, "{{VirtualPath}}");
        var target = SinglePath(context, TargetKey);
        if (source == null || target == null)
            return EventActionResult.Failed("The source or the target is empty.");
        var files = await FileOperations.CopyAsync(fileSystem, source, target, context.BoolOption(OverwriteKey), ct);
        return EventActionResult.Ok($"Copied {source} to {target} ({files} files).");
    }
}
