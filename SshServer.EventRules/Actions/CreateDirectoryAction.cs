using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Storage;

namespace SshServer.EventRules.Actions;

/// <summary>Creates directories of the user, with their missing parents. An existing directory is not an error.</summary>
public sealed class CreateDirectoryAction : UserFileAction
{
    public CreateDirectoryAction(UserFileSystems fileSystems) : base(fileSystems)
    {
    }

    public override string Type => "CreateDirectory";

    public override string DisplayName => "Create directories";

    public override string Description => "Creates directories in the storage of the user.";

    public override IReadOnlyList<EventActionField> Fields { get; } = [PathsField("Directories", defaultValue: null)];

    public override IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options) => Required(options, (PathsKey, "directories"));

    protected override async Task<EventActionResult> ExecuteAsync(EventActionContext context, IFileSystem fileSystem, CancellationToken ct)
    {
        var paths = Paths(context, fallback: "");
        if (paths.Count == 0)
            return EventActionResult.Failed("The directories are empty.");
        foreach (var path in paths)
            await FileOperations.EnsureDirectoryAsync(fileSystem, path, ct);
        return EventActionResult.Ok($"Created {string.Join(", ", paths)}.");
    }
}
