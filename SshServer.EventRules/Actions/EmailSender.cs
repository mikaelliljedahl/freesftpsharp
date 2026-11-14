using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace SshServer.EventRules.Actions;

/// <summary>A file attached to an email.</summary>
public sealed record EmailAttachment(string FileName, byte[] Content);

/// <summary>One email of an Email action.</summary>
public sealed record EmailMessage(IReadOnlyList<string> To, string Subject, string Body)
{
    public IReadOnlyList<EmailAttachment> Attachments { get; init; } = [];
}

/// <summary>Sends the emails of the Email action. The tests replace it with a fake.</summary>
public interface IEmailSender
{
    /// <summary>False when no mail server is configured: the Email action is skipped.</summary>
    bool IsConfigured { get; }

    Task SendAsync(EmailMessage message, CancellationToken ct);
}

/// <summary>SMTP with MailKit, configured in <c>EventRules:Smtp</c> (<see cref="SmtpOptions"/>).</summary>
public sealed class SmtpEmailSender : IEmailSender
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    private readonly SmtpOptions _options;

    public SmtpEmailSender(IOptions<EventRuleOptions> options)
    {
        _options = options.Value.Smtp;
    }

    public bool IsConfigured => _options.IsConfigured;

    public async Task SendAsync(EmailMessage message, CancellationToken ct)
    {
        if (!IsConfigured)
            throw new InvalidOperationException("No mail server is configured (EventRules:Smtp:Host).");

        var mime = new MimeMessage();
        mime.From.Add(MailboxAddress.Parse(_options.From!));
        foreach (var to in message.To)
            mime.To.Add(MailboxAddress.Parse(to));
        mime.Subject = message.Subject;
        var body = new BodyBuilder { TextBody = message.Body };
        foreach (var attachment in message.Attachments)
            body.Attachments.Add(attachment.FileName, attachment.Content);
        mime.Body = body.ToMessageBody();

        using var client = new SmtpClient { Timeout = (int)Timeout.TotalMilliseconds };
        var security = _options.Security switch
        {
            SmtpSecurity.None => SecureSocketOptions.None,
            SmtpSecurity.StartTls => SecureSocketOptions.StartTls,
            SmtpSecurity.SslOnConnect => SecureSocketOptions.SslOnConnect,
            _ => SecureSocketOptions.Auto,
        };
        await client.ConnectAsync(_options.Host!, _options.Port, security, ct);
        if (!string.IsNullOrEmpty(_options.Username))
            await client.AuthenticateAsync(_options.Username, _options.Password ?? string.Empty, ct);
        await client.SendAsync(new MailKit.SendRequest(mime), ct);
        await client.DisconnectAsync(quit: true, ct);
    }
}
