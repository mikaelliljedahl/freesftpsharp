using System.Net.Mail;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Storage;

namespace SshServer.EventRules.Actions;

/// <summary>
/// Sends an email with placeholders in the subject and the body, optionally with the file of the event attached (up to
/// <see cref="SmtpOptions.MaxAttachmentBytes"/>). Without a configured mail server it is skipped, not failed.
/// </summary>
public sealed class EmailAction : IEventRuleAction
{
    public const string ToKey = "To";
    public const string SubjectKey = "Subject";
    public const string BodyKey = "Body";
    public const string AttachFileKey = "AttachFile";

    private readonly IEmailSender _sender;
    private readonly UserFileSystems _fileSystems;
    private readonly SmtpOptions _options;

    public EmailAction(IEmailSender sender, UserFileSystems fileSystems, IOptions<EventRuleOptions> options)
    {
        _sender = sender;
        _fileSystems = fileSystems;
        _options = options.Value.Smtp;
    }

    public string Type => "Email";

    public string DisplayName => "Email";

    public string Description => "Sends an email through the mail server of EventRules:Smtp.";

    public bool NeedsUser => false;

    public IReadOnlyList<EventActionField> Fields { get; } =
    [
        new(ToKey, "To", EventActionFieldKind.Text) { Help = "One or more addresses, separated by commas." },
        new(SubjectKey, "Subject", EventActionFieldKind.Text) { DefaultValue = "{{Event}} {{VirtualPath}} by {{Username}}", Placeholders = true },
        new(BodyKey, "Text", EventActionFieldKind.MultilineText)
        {
            DefaultValue = "The rule {{Rule}} ran on {{Event}}.\nUser: {{Username}}\nPath: {{VirtualPath}}\nSize: {{FileSize}} bytes\nTime: {{Timestamp}}",
            Placeholders = true,
        },
        new(AttachFileKey, "Attach the file of the event", EventActionFieldKind.Boolean),
    ];

    public IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options)
    {
        var to = Recipients(options.GetValueOrDefault(ToKey));
        if (to.Count == 0)
            return ["Enter one or more addresses."];
        return to.Where(a => !MailAddress.TryCreate(a, out _)).Select(a => $"{a} is not a valid email address.").ToArray();
    }

    public async Task<EventActionResult> ExecuteAsync(EventActionContext context, CancellationToken ct)
    {
        if (!_sender.IsConfigured)
            return EventActionResult.Skipped("No mail server is configured (EventRules:Smtp:Host).");

        var to = Recipients(context.Option(ToKey));
        if (to.Count == 0)
            return EventActionResult.Failed("No address.");
        // A file name can have a line break; a subject cannot.
        var subject = context.RenderOption(SubjectKey).ReplaceLineEndings(" ");
        var body = context.RenderOption(BodyKey);
        var attachments = new List<EmailAttachment>();
        var note = string.Empty;
        if (context.BoolOption(AttachFileKey) && context.User != null && context.Event is FileEvent file)
        {
            var path = VirtualPath.Normalize(file.VirtualPath);
            var fileSystem = await _fileSystems.OpenAsync(context.User, ct);
            var content = await FileOperations.ReadAllAsync(fileSystem, path, _options.MaxAttachmentBytes, ct);
            if (content == null)
                note = $" The file is larger than {_options.MaxAttachmentBytes} bytes and is not attached.";
            else
                attachments.Add(new EmailAttachment(VirtualPath.GetName(path), content));
        }

        await _sender.SendAsync(new EmailMessage(to, subject, body) { Attachments = attachments }, ct);
        return EventActionResult.Ok($"Sent to {string.Join(", ", to)}.{note}");
    }

    private static IReadOnlyList<string> Recipients(string? text)
        => (text ?? string.Empty).Split([',', ';', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
