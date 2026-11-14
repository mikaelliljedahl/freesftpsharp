using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Storage;

namespace SshServer.EventRules.Actions;

/// <summary>Removes files or directories of the user. A directory must be empty, unless the action removes its content too.</summary>
public sealed class DeleteAction : UserFileAction
{
    public const string RecursiveKey = "Recursive";

    public DeleteAction(UserFileSystems fileSystems) : base(fileSystems)
    {
    }

    public override string Type => "Delete";

    public override string DisplayName => "Delete";

    public override string Description => "Removes files or directories of the user.";

    public override IReadOnlyList<EventActionField> Fields { get; } =
    [
        PathsField("Paths"),
        new(RecursiveKey, "Remove a directory with its content", EventActionFieldKind.Boolean),
    ];

    public override IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options) => [];

    protected override async Task<EventActionResult> ExecuteAsync(EventActionContext context, IFileSystem fileSystem, CancellationToken ct)
    {
        var paths = Paths(context);
        if (paths.Contains(VirtualPath.Root))
            return EventActionResult.Failed("The user root is never removed.");
        var files = 0;
        foreach (var path in paths)
            files += await FileOperations.DeleteAsync(fileSystem, path, context.BoolOption(RecursiveKey), ct);
        return EventActionResult.Ok($"Removed {string.Join(", ", paths)} ({files} files).");
    }
}
