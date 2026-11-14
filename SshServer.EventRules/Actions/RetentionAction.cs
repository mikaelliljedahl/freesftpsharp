using System.Globalization;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Storage;

namespace SshServer.EventRules.Actions;

/// <summary>
/// Data retention: removes the files of the user in the folders (and below) whose last write is older than the number
/// of days, optionally also the directories that are empty then (never the folder itself). The next actions get the
/// count as <c>{{RetentionDeleted}}</c> and a report as <c>{{RetentionReport}}</c>, for example for an email.
/// </summary>
public sealed class RetentionAction : UserFileAction
{
    public const string FoldersKey = "Folders";
    public const string RetainDaysKey = "RetainDays";
    public const string DeleteEmptyDirectoriesKey = "DeleteEmptyDirectories";
    public const string DeletedValue = "RetentionDeleted";
    public const string ReportValue = "RetentionReport";

    public RetentionAction(UserFileSystems fileSystems) : base(fileSystems)
    {
    }

    public override string Type => "Retention";

    public override string DisplayName => "Data retention";

    public override string Description => "Removes the files older than a number of days in folders of the user.";

    public override IReadOnlyList<EventActionField> Fields { get; } =
    [
        new(FoldersKey, "Folders", EventActionFieldKind.MultilineText) { Help = "One virtual path per line, for example /tmp.", Placeholders = true },
        new(RetainDaysKey, "Keep files for (days)", EventActionFieldKind.Number) { DefaultValue = "30" },
        new(DeleteEmptyDirectoriesKey, "Remove the directories that are empty then", EventActionFieldKind.Boolean),
    ];

    public override IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options)
    {
        var errors = Required(options, (FoldersKey, "folders")).ToList();
        if (!options.TryGetValue(RetainDaysKey, out var days) || !int.TryParse(days, NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value < 1)
            errors.Add("Keep files for 1 day or more.");
        return errors;
    }

    protected override async Task<EventActionResult> ExecuteAsync(EventActionContext context, IFileSystem fileSystem, CancellationToken ct)
    {
        if (!int.TryParse(context.Option(RetainDaysKey), NumberStyles.None, CultureInfo.InvariantCulture, out var days) || days < 1)
            return EventActionResult.Failed("The number of days is not valid.");
        var cutoff = context.Now.UtcDateTime - TimeSpan.FromDays(days);
        var deleteEmpty = context.BoolOption(DeleteEmptyDirectoriesKey);
        var lines = new List<string>();
        var total = 0;
        foreach (var folder in Paths(context, FoldersKey, fallback: ""))
        {
            var entry = await fileSystem.StatAsync(folder, followLinks: true, ct);
            if (entry is not { IsDirectory: true })
            {
                lines.Add($"{context.User!.Username}: {folder} is not a directory; nothing removed.");
                continue;
            }
            var removed = await CleanAsync(fileSystem, folder, cutoff, deleteEmpty, ct);
            total += removed.Files;
            lines.Add($"{context.User!.Username}: removed {removed.Files} files older than {days} days in {folder}" +
                (deleteEmpty ? $" and {removed.Directories} empty directories." : "."));
        }

        var before = context.Values.TryGetValue(DeletedValue, out var earlier) && int.TryParse(earlier, CultureInfo.InvariantCulture, out var n) ? n : 0;
        context.Values[DeletedValue] = (before + total).ToString(CultureInfo.InvariantCulture);
        var report = string.Join(Environment.NewLine, lines);
        context.Values[ReportValue] = context.Values.TryGetValue(ReportValue, out var previous) && previous.Length > 0
            ? previous + Environment.NewLine + report
            : report;
        return EventActionResult.Ok(report);
    }

    private static async Task<(int Files, int Directories)> CleanAsync(IFileSystem fileSystem, string directory, DateTime cutoffUtc, bool deleteEmpty,
        CancellationToken ct)
    {
        var entries = new List<FileSystemEntry>();
        await foreach (var entry in fileSystem.ListAsync(directory, ct))
            entries.Add(entry);

        var files = 0;
        var directories = 0;
        foreach (var entry in entries)
        {
            var path = VirtualPath.Combine(directory, entry.Name);
            switch (entry.Type)
            {
                case FileSystemEntryType.File when entry.LastWriteTimeUtc < cutoffUtc:
                    await fileSystem.DeleteFileAsync(path, ct);
                    files++;
                    break;
                case FileSystemEntryType.Directory:
                    var below = await CleanAsync(fileSystem, path, cutoffUtc, deleteEmpty, ct);
                    files += below.Files;
                    directories += below.Directories;
                    if (deleteEmpty && await IsEmptyAsync(fileSystem, path, ct))
                    {
                        await fileSystem.DeleteDirectoryAsync(path, ct);
                        directories++;
                    }
                    break;
            }
        }
        return (files, directories);
    }

    private static async Task<bool> IsEmptyAsync(IFileSystem fileSystem, string path, CancellationToken ct)
    {
        await foreach (var _ in fileSystem.ListAsync(path, ct))
            return false;
        return true;
    }
}
