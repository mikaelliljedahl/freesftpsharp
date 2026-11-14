using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.EventRules;

namespace SshServer.EventRules.Actions;

/// <summary>A process to start: the arguments are separate values (no shell), the environment is only <see cref="Environment"/>.</summary>
public sealed record CommandRequest(string Executable, IReadOnlyList<string> Arguments, IReadOnlyDictionary<string, string> Environment, TimeSpan Timeout);

/// <summary>The end of a process: its exit code (null after a timeout) and the start of its output.</summary>
public sealed record CommandResult(int? ExitCode, bool TimedOut, string Output);

/// <summary>Starts the processes of the Command action. The tests replace it with a fake.</summary>
public interface ICommandRunner
{
    Task<CommandResult> RunAsync(CommandRequest request, CancellationToken ct);
}

/// <summary>
/// <see cref="ICommandRunner"/> with <see cref="Process"/>: no shell (<see cref="ProcessStartInfo.ArgumentList"/>), the
/// environment of the server cleared, the working directory the temporary directory, the process tree killed at the
/// timeout. It keeps the first 2 KiB of the output.
/// </summary>
public sealed class ProcessCommandRunner : ICommandRunner
{
    public const int MaxOutputChars = 2048;

    public async Task<CommandResult> RunAsync(CommandRequest request, CancellationToken ct)
    {
        var start = new ProcessStartInfo(request.Executable)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetTempPath(),
        };
        foreach (var argument in request.Arguments)
            start.ArgumentList.Add(argument);
        start.Environment.Clear();
        foreach (var (name, value) in request.Environment)
            start.Environment[name] = value;

        using var process = new Process { StartInfo = start };
        var output = new StringBuilder();
        void Collect(object sender, DataReceivedEventArgs e)
        {
            if (e.Data == null)
                return;
            lock (output)
            {
                if (output.Length < MaxOutputChars)
                    output.AppendLine(e.Data.Length > MaxOutputChars ? e.Data[..MaxOutputChars] : e.Data);
            }
        }
        process.OutputDataReceived += Collect;
        process.ErrorDataReceived += Collect;
        process.Start();
        process.StandardInput.Close();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(request.Timeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // It ended at the same time.
            }
            ct.ThrowIfCancellationRequested();
            return new CommandResult(null, true, Text(output));
        }
        await process.WaitForExitAsync(CancellationToken.None); // the output is read to the end
        return new CommandResult(process.ExitCode, false, Text(output));
    }

    private static string Text(StringBuilder output)
    {
        lock (output)
        {
            var text = output.ToString().Trim();
            return text.Length > MaxOutputChars ? text[..MaxOutputChars] : text;
        }
    }
}

/// <summary>
/// Starts an executable of the operator. Off unless <see cref="EventRuleOptions.AllowCommands"/> is true, and only the
/// executables in <see cref="EventRuleOptions.AllowedCommands"/>. The arguments (one per line) and the environment
/// (<c>NAME=value</c> per line) can have placeholders; each argument is one value for the process, never parsed by a
/// shell, and the environment of the server is not passed on. Exit code 0 is success; after
/// <see cref="EventRuleOptions.CommandTimeoutSeconds"/> the process is killed.
/// </summary>
public sealed partial class CommandAction : IEventRuleAction
{
    public const string CommandKey = "Command";
    public const string ArgumentsKey = "Arguments";
    public const string EnvironmentKey = "Environment";

    private readonly ICommandRunner _runner;
    private readonly EventRuleOptions _options;

    public CommandAction(ICommandRunner runner, IOptions<EventRuleOptions> options)
    {
        _runner = runner;
        _options = options.Value;
    }

    public string Type => "Command";

    public string DisplayName => "Command";

    public string Description => "Starts an executable that the operator allows in EventRules:AllowedCommands.";

    public bool NeedsUser => false;

    public IReadOnlyList<EventActionField> Fields => new EventActionField[]
    {
        new(CommandKey, "Executable", EventActionFieldKind.Choice) { Choices = _options.AllowedCommands, Help = "The absolute path, from EventRules:AllowedCommands." },
        new(ArgumentsKey, "Arguments", EventActionFieldKind.MultilineText) { Help = "One argument per line; no shell.", Placeholders = true },
        new(EnvironmentKey, "Environment", EventActionFieldKind.MultilineText)
        {
            Help = "NAME=value, one per line. The environment of the server is not passed on.",
            Placeholders = true,
        },
    };

    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.CultureInvariant)]
    private static partial Regex VariableName();

    public IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options)
    {
        if (Refusal(options.GetValueOrDefault(CommandKey)) is { } refusal)
            return [refusal];
        var errors = new List<string>();
        foreach (var line in Lines(options.GetValueOrDefault(EnvironmentKey)))
        {
            var equals = line.IndexOf('=');
            if (equals <= 0 || !VariableName().IsMatch(line[..equals]))
                errors.Add($"The environment line '{line}' must be NAME=value.");
        }
        return errors;
    }

    public async Task<EventActionResult> ExecuteAsync(EventActionContext context, CancellationToken ct)
    {
        var executable = context.Option(CommandKey);
        // The configuration can change after the rule was saved: check it again.
        if (Refusal(executable) is { } refusal)
            return EventActionResult.Failed(refusal);

        var arguments = Lines(context.Option(ArgumentsKey)).Select(context.Render).ToArray();
        var environment = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in Lines(context.Option(EnvironmentKey)))
        {
            var equals = line.IndexOf('=');
            if (equals > 0 && VariableName().IsMatch(line[..equals]))
                environment[line[..equals]] = context.Render(line[(equals + 1)..]);
        }

        var result = await _runner.RunAsync(new CommandRequest(executable.Trim(), arguments, environment,
            TimeSpan.FromSeconds(_options.CommandTimeoutSeconds)), ct);
        var output = string.IsNullOrEmpty(result.Output) ? string.Empty : " Output: " + result.Output;
        if (result.TimedOut)
            return EventActionResult.Failed($"{executable} did not end within {_options.CommandTimeoutSeconds} s and was killed.{output}");
        return result.ExitCode == 0
            ? EventActionResult.Ok($"{executable} ended with exit code 0.{output}")
            : EventActionResult.Failed($"{executable} ended with exit code {result.ExitCode}.{output}");
    }

    /// <summary>Why the executable may not run; null when it may.</summary>
    private string? Refusal(string? executable)
    {
        if (!_options.AllowCommands)
            return "Commands are disabled on this server. The operator turns them on with EventRules:AllowCommands=true and EventRules:AllowedCommands.";
        if (string.IsNullOrWhiteSpace(executable))
            return "Select the executable.";
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var trimmed = executable.Trim();
        if (!Path.IsPathFullyQualified(trimmed) || !_options.AllowedCommands.Any(allowed => string.Equals(Path.GetFullPath(allowed), Path.GetFullPath(trimmed), comparison)))
            return $"{trimmed} is not in EventRules:AllowedCommands.";
        return null;
    }

    private static IEnumerable<string> Lines(string? text)
        => (text ?? string.Empty).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.TrimEnd('\r')).Where(l => l.Trim().Length > 0);
}
