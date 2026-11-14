using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Storage;

namespace SshServer.EventRules.Actions;

/// <summary>Fails when a path of the user does not exist: with "stop on failure" the next actions run only when the files are there.</summary>
public sealed class ExistsAction : UserFileAction
{
    public ExistsAction(UserFileSystems fileSystems) : base(fileSystems)
    {
    }

    public override string Type => "Exists";

    public override string DisplayName => "Check that files exist";

    public override string Description => "Fails when one of the paths does not exist.";

    public override IReadOnlyList<EventActionField> Fields { get; } = [PathsField("Paths", defaultValue: null)];

    public override IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options) => Required(options, (PathsKey, "paths"));

    protected override async Task<EventActionResult> ExecuteAsync(EventActionContext context, IFileSystem fileSystem, CancellationToken ct)
    {
        var missing = new List<string>();
        var paths = Paths(context, fallback: "");
        foreach (var path in paths)
        {
            if (await fileSystem.StatAsync(path, followLinks: true, ct) == null)
                missing.Add(path);
        }
        return missing.Count == 0
            ? EventActionResult.Ok($"{string.Join(", ", paths)} exist.")
            : EventActionResult.Failed($"Missing: {string.Join(", ", missing)}.");
    }
}
