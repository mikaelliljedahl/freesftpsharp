using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace SshServer.Api;

/// <summary>
/// The rate limits of the routes without login (<c>POST /api/v1/token</c> and <c>/api/v1/health</c>), per client address
/// and minute. The endpoint filter of <see cref="For"/> answers 429 with a <c>Retry-After</c> header.
/// </summary>
internal sealed class ApiRateLimits : IDisposable
{
    public const string Token = "token";
    public const string Anonymous = "anonymous";

    private readonly Dictionary<string, PartitionedRateLimiter<string>> _limiters;

    public ApiRateLimits(IOptions<ApiOptions> options)
    {
        _limiters = new Dictionary<string, PartitionedRateLimiter<string>>(StringComparer.Ordinal)
        {
            [Token] = Create(options.Value.TokenRequestsPerMinute),
            [Anonymous] = Create(options.Value.AnonymousRequestsPerMinute),
        };
    }

    public static Func<EndpointFilterInvocationContext, EndpointFilterDelegate, ValueTask<object?>> For(string policy) =>
        async (context, next) =>
        {
            var limits = context.HttpContext.RequestServices.GetRequiredService<ApiRateLimits>();
            var client = context.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "(unknown)";
            using var lease = limits._limiters[policy].AttemptAcquire(client);
            if (lease.IsAcquired)
                return await next(context);
            context.HttpContext.Response.Headers.RetryAfter = "60";
            return Results.Problem("Too many requests. Try again later.", statusCode: StatusCodes.Status429TooManyRequests);
        };

    private static PartitionedRateLimiter<string> Create(int permitsPerMinute) =>
        PartitionedRateLimiter.Create<string, string>(client => RateLimitPartition.GetFixedWindowLimiter(client, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitsPerMinute,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        }));

    public void Dispose()
    {
        foreach (var limiter in _limiters.Values)
            limiter.Dispose();
    }
}
