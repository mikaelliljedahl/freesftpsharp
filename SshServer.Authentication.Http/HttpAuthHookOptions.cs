using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Security;

namespace SshServer.Authentication.Http;

/// <summary>
/// The external HTTP authentication hook (issue #64), section <c>Auth:HttpHook</c>. Off while <see cref="Url"/> is empty.
/// </summary>
public sealed class HttpAuthHookOptions
{
    public const string SectionName = "Auth:HttpHook";
    public const int DefaultTimeoutSeconds = 10;
    public const int MaxTimeoutSeconds = 60;
    public const int MinSecretLength = 16;

    /// <summary>
    /// The URL that gets a <c>POST</c> for every login of a user of the hook (and of an unknown user). <c>https://</c>, or
    /// <c>http://</c> only to a loopback address (localhost, 127.0.0.0/8, ::1), because the request has the password.
    /// </summary>
    public string? Url { get; set; }

    /// <summary>
    /// The HMAC-SHA256 key of the <c>X-FreeSftpSharp-Signature</c> header (the same format as the webhooks), so the
    /// service can verify that the request comes from this server. At least 16 characters. Empty: no signature. Put it in
    /// an environment variable or the user secrets, not in appsettings.json.
    /// </summary>
    [Secret]
    public string? Secret { get; set; }

    /// <summary>The time for one answer, 1 to 60 seconds. No answer in time: the login is refused.</summary>
    public int TimeoutSeconds { get; set; } = DefaultTimeoutSeconds;

    /// <summary>Whether the hook is asked for public key logins too (default). Off: only passwords.</summary>
    public bool PublicKeys { get; set; } = true;

    public bool Enabled => !string.IsNullOrWhiteSpace(Url);

    public static void Bind(HttpAuthHookOptions options, IConfiguration configuration) =>
        configuration.GetSection(SectionName).Bind(options);
}

public sealed class HttpAuthHookOptionsValidator : IValidateOptions<HttpAuthHookOptions>
{
    public ValidateOptionsResult Validate(string? name, HttpAuthHookOptions options)
    {
        var errors = new List<string>();
        if (ValidateUrl(options.Url) is { } urlError)
            errors.Add(urlError);
        if (!string.IsNullOrEmpty(options.Secret) && options.Secret.Length < HttpAuthHookOptions.MinSecretLength)
            errors.Add($"{HttpAuthHookOptions.SectionName}:Secret must have at least {HttpAuthHookOptions.MinSecretLength} characters.");
        if (options.TimeoutSeconds is < 1 or > HttpAuthHookOptions.MaxTimeoutSeconds)
            errors.Add($"{HttpAuthHookOptions.SectionName}:TimeoutSeconds must be 1 to {HttpAuthHookOptions.MaxTimeoutSeconds}.");
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }

    /// <summary>Absolute, no credentials in it, <c>https://</c> or <c>http://</c> to a loopback address.</summary>
    public static string? ValidateUrl(string? url)
    {
        var section = HttpAuthHookOptions.SectionName;
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
            return $"{section}:Url must be an absolute URL, for example https://auth.example.com/sftp.";
        if (!string.IsNullOrEmpty(uri.UserInfo))
            return $"{section}:Url cannot have a user name or password.";
        if (uri.Scheme == Uri.UriSchemeHttps)
            return null;
        if (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)
            return null;
        return $"{section}:Url must start with https:// (http:// only to localhost): the request has the password.";
    }
}
