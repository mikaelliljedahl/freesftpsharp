using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace SshServer.Api;

/// <summary>
/// The configuration section "Api" of the REST API (#67). The API is off until <see cref="Enabled"/> is true; then every
/// route under <c>/api/v1</c> needs a bearer token or an API key of an administrator, except <c>/api/v1/health</c> and
/// <c>POST /api/v1/token</c>.
/// </summary>
public sealed class ApiOptions
{
    public const string SectionName = "Api";

    public bool Enabled { get; set; }

    /// <summary>The lifetime of a bearer token from <c>POST /api/v1/token</c>, in minutes (1 to 1440).</summary>
    public int TokenLifetimeMinutes { get; set; } = 20;

    /// <summary>The requests per minute and client address to <c>POST /api/v1/token</c> (failed logins are also throttled like the admin UI login).</summary>
    public int TokenRequestsPerMinute { get; set; } = 10;

    /// <summary>The requests per minute and client address to the other route without login (<c>/api/v1/health</c>).</summary>
    public int AnonymousRequestsPerMinute { get; set; } = 60;

    public static ApiOptions FromConfiguration(IConfiguration configuration)
    {
        var options = new ApiOptions();
        configuration.GetSection(SectionName).Bind(options);
        return options;
    }
}

/// <summary>Checks <see cref="ApiOptions"/> at the start.</summary>
public sealed class ApiOptionsValidator : IValidateOptions<ApiOptions>
{
    public ValidateOptionsResult Validate(string? name, ApiOptions options)
    {
        var problems = new List<string>();
        if (options.TokenLifetimeMinutes is < 1 or > 1440)
            problems.Add("Api:TokenLifetimeMinutes must be from 1 to 1440.");
        if (options.TokenRequestsPerMinute < 1)
            problems.Add("Api:TokenRequestsPerMinute must be at least 1.");
        if (options.AnonymousRequestsPerMinute < 1)
            problems.Add("Api:AnonymousRequestsPerMinute must be at least 1.");
        return problems.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(problems);
    }
}
