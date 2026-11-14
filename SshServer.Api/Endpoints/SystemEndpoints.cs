using System.Diagnostics;
using System.Reflection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using SshServer.Administration;
using SshServer.Api.Authentication;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Audit;
using SshServer.Interfaces.Events;
using SshServer.Webhooks;

namespace SshServer.Api.Endpoints;

/// <summary>The login of <c>POST /api/v1/token</c>. <see cref="TotpCode"/> is for the admin two-factor login (#63).</summary>
public sealed record TokenRequest(string? Username, string? Password, string? TotpCode);

/// <summary>The answer of <c>/api/v1/health</c>: the API answers. Readiness (database, listeners) is <c>/readyz</c> (Observability).</summary>
public sealed record HealthView(string Status);

/// <summary>The server as the caller sees it.</summary>
public sealed record StatusView(string Version, DateTimeOffset StartedAt, long UptimeSeconds, string NodeId, string Administrator,
    IReadOnlyList<string> Permissions, int? ScopeRoleId, bool AuditLog, bool Webhooks);

/// <summary>/api/v1/token, /api/v1/token/refresh, /api/v1/health and /api/v1/status.</summary>
internal static class SystemEndpoints
{
    /// <summary>The <see cref="AuthEvent.Protocol"/> of the API logins in the audit log.</summary>
    public const string AuditProtocol = "API";

    public const string InvalidCredentials = "Invalid user name or password.";

    public static void Map(RouteGroupBuilder api)
    {
        api.MapPost("/token", TokenAsync)
            .AllowAnonymous().AddEndpointFilter(ApiRateLimits.For(ApiRateLimits.Token))
            .WithTags("Authentication").WithName("CreateToken")
            .WithSummary("A bearer token for an administrator (user name and password; the same lockout as the admin UI login).")
            .ProducesProblem(StatusCodes.Status401Unauthorized).ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);

        api.MapPost("/token/refresh", async Task<Results<Ok<ApiToken>, ProblemHttpResult>> (HttpContext http, IAdminStore admins, ApiTokenService tokens) =>
            {
                if (ApiAuthentication.UsesApiKey(http.User))
                    return ApiResults.Forbidden("An API key does not need a token.");
                var admin = await admins.GetAdminAsync(http.User.Identity?.Name ?? "", http.RequestAborted);
                return admin == null ? ApiResults.Forbidden("The administrator does not exist any more.") : TypedResults.Ok(tokens.Issue(admin));
            })
            .WithTags("Authentication").WithName("RefreshToken").WithSummary("A new bearer token for the caller of a valid one.").WithErrors();

        api.MapGet("/health", () => TypedResults.Ok(new HealthView("ok")))
            .AllowAnonymous().AddEndpointFilter(ApiRateLimits.For(ApiRateLimits.Anonymous))
            .WithTags("Status").WithName("Health").WithSummary("Answers without login when the API runs.");

        api.MapGet("/status", (CurrentAdmin current, IAuditLog audit, WebhookAdministrationService webhooks) =>
            {
                var actor = current.Actor;
                using var process = Process.GetCurrentProcess();
                var started = new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
                return TypedResults.Ok(new StatusView(Version(), started, (long)(DateTimeOffset.UtcNow - started).TotalSeconds,
                    Environment.MachineName, actor.AuditName, PermissionNames.Of(actor.Permissions), actor.ScopeRoleId,
                    audit.IsEnabled, webhooks.IsEnabled));
            })
            .WithTags("Status").WithName("Status").WithSummary("The version, uptime and node of the server, and the permissions of the caller.")
            .WithErrors();
    }

    private static async Task<Results<Ok<ApiToken>, ProblemHttpResult>> TokenAsync(TokenRequest request, HttpContext http,
        AdminCredentialValidator validator, LoginThrottle throttle, ITokenSecondFactor secondFactor, AdminAdministrationService administration,
        ApiTokenService tokens, IEventBus events, TimeProvider time, ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger("SshServer.Api.Token");
        var ct = http.RequestAborted;
        var client = http.Connection.RemoteIpAddress?.ToString();
        if (throttle.IsLockedOut(client))
        {
            logger.LogWarning("API token refused for {Client}: locked out after too many failures.", client);
            return TypedResults.Problem("Too many failed logins. Try again later.", statusCode: StatusCodes.Status429TooManyRequests);
        }

        var admin = await validator.ValidateAsync(request.Username, request.Password, http.Connection.RemoteIpAddress, ct);
        if (admin == null || !await secondFactor.IsSatisfiedAsync(admin, request.TotpCode, ct))
        {
            throttle.RecordFailure(client);
            logger.LogWarning("Failed API login for user {UserName} from {Client}.", request.Username, client);
            await PublishAsync(events, time, AuthEventType.LoginFailed, request.Username, client, ct);
            return TypedResults.Problem(admin == null ? InvalidCredentials : "The second factor code is missing or not valid.",
                statusCode: StatusCodes.Status401Unauthorized, title: "Unauthorized");
        }

        throttle.RecordSuccess(client);
        if (admin.MustChangePassword)
            return ApiResults.Forbidden("The administrator must set a new password first: log in to the admin UI.");

        await administration.RecordLoginAsync(admin, ct);
        await PublishAsync(events, time, AuthEventType.LoginOk, admin.Username, client, ct);
        logger.LogInformation("Admin {UserName} got an API token from {Client}.", admin.Username, client);
        return TypedResults.Ok(tokens.Issue(admin));
    }

    private static ValueTask PublishAsync(IEventBus events, TimeProvider time, AuthEventType type, string? username, string? client, CancellationToken ct) =>
        events.PublishAsync(new AuthEvent(type)
        {
            Timestamp = time.GetUtcNow(),
            Username = username?.Trim(),
            RemoteIp = client,
            Protocol = AuditProtocol,
            Method = "password",
            Reason = type == AuthEventType.LoginFailed ? "wrong user name or password, second factor, disabled account or address not allowed" : null,
        }, ct);

    private static string Version()
    {
        var assembly = Assembly.GetEntryAssembly() ?? typeof(SystemEndpoints).Assembly;
        return assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
               ?? assembly.GetName().Version?.ToString() ?? "unknown";
    }
}
