using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace SshServer.TwoFactor;

/// <summary>The settings of the TOTP second factor (section <c>Auth:Totp</c>). Nothing is required.</summary>
public sealed class TwoFactorOptions
{
    public const string SectionName = "Auth:Totp";
    public const string DefaultIssuer = "FreeSftpSharp";

    /// <summary>The issuer that the authenticator app shows next to the account name (the label of the QR code).</summary>
    public string Issuer { get; set; } = DefaultIssuer;

    /// <summary>Wrong codes of one user or administrator within <see cref="LockoutMinutes"/> before its codes are refused.</summary>
    public int MaxFailedCodes { get; set; } = 5;

    /// <summary>How long the codes of a user or administrator are refused after too many wrong codes.</summary>
    public int LockoutMinutes { get; set; } = 5;

    internal static void Bind(TwoFactorOptions options, IConfiguration configuration) =>
        configuration.GetSection(SectionName).Bind(options);
}

internal sealed class TwoFactorOptionsValidator : IValidateOptions<TwoFactorOptions>
{
    public ValidateOptionsResult Validate(string? name, TwoFactorOptions options)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(options.Issuer) || options.Issuer.Length > 64 || options.Issuer.Contains(':'))
            errors.Add($"{TwoFactorOptions.SectionName}:Issuer must be 1 to 64 characters without ':'.");
        if (options.MaxFailedCodes < 1)
            errors.Add($"{TwoFactorOptions.SectionName}:MaxFailedCodes must be at least 1.");
        if (options.LockoutMinutes < 1)
            errors.Add($"{TwoFactorOptions.SectionName}:LockoutMinutes must be at least 1.");
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
