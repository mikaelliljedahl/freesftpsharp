using System;
using System.Threading;
using System.Threading.Tasks;
using FxSshSftpServer.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Users;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The web client of the SFTP users (#69) in the admin host: the pages under <c>/client</c> (Razor Pages in
    /// Pages/Client), the endpoints under <c>/client/api</c> (<see cref="ClientApi"/>), the cookie scheme
    /// <see cref="ClientAuth.Scheme"/> and its policies. Off unless <c>WebClient:Enabled</c> is true
    /// (<see cref="WebClientOptions"/>); then every <c>/client</c> path answers 404.
    /// </summary>
    public static class WebClientSetup
    {
        public const string ContentSecurityPolicy =
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; " +
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

        public static IServiceCollection AddWebClient(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddOptions<WebClientOptions>().Bind(configuration.GetSection(WebClientOptions.SectionName)).ValidateOnStart();
            services.AddSingleton<IValidateOptions<WebClientOptions>, WebClientOptionsValidator>();
            services.AddSingleton<ClientSessions>();
            services.AddSingleton<UploadSessions>();
            services.AddSingleton<ClientStorageFactory>();
            services.AddSingleton<ClientAccountService>();
            services.AddSingleton<ClientPasswordChange>();
            services.AddSingleton<ClientLoginFlow>();
            services.AddSingleton<ClientPendingLogin>();
            services.AddSingleton(sp =>
            {
                var options = sp.GetRequiredService<IOptions<WebClientOptions>>().Value;
                return new ClientLoginThrottle(new LoginThrottle(sp.GetRequiredService<TimeProvider>(), Math.Max(1, options.MaxFailedLogins),
                    TimeSpan.FromMinutes(Math.Max(1, options.LockoutMinutes))));
            });
            // The share links (#70): off unless the web client is on and ServerSettings.Shares allows them.
            services.AddSingleton<ShareAccess>();
            services.AddSingleton<ShareSessions>();
            services.AddSingleton<ShareService>();
            services.AddSingleton<ShareRateLimiter>();
            services.AddHostedService<ClientSessionSweeper>();

            services.AddAuthentication().AddCookie(ClientAuth.Scheme, options =>
            {
                options.Cookie.Name = ClientAuth.CookieName;
                options.Cookie.Path = ClientAuth.CookiePath; // the browser never sends it to the admin UI
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.LoginPath = ClientAuth.LoginPath;
                options.LogoutPath = "/client/logout";
                options.AccessDeniedPath = ClientAuth.LoginPath;
                // The idle end of a session is ClientSessions; this is the longest life of one cookie.
                options.ExpireTimeSpan = TimeSpan.FromHours(12);
                options.SlidingExpiration = true;
                options.Events = new CookieAuthenticationEvents
                {
                    OnRedirectToLogin = RedirectToLoginAsync,
                    OnRedirectToAccessDenied = AccessDeniedAsync,
                    OnValidatePrincipal = ValidatePrincipalAsync,
                };
            });

            services.AddAuthorization(options =>
            {
                options.AddPolicy(ClientAuth.UserPolicy, policy => policy
                    .AddAuthenticationSchemes(ClientAuth.Scheme)
                    .RequireAuthenticatedUser()
                    .RequireRole(ClientClaims.Role)
                    .RequireAssertion(context => !ClientClaims.MustChangePassword(context.User)));
                options.AddPolicy(ClientAuth.PasswordChangePolicy, policy => policy
                    .AddAuthenticationSchemes(ClientAuth.Scheme)
                    .RequireAuthenticatedUser()
                    .RequireRole(ClientClaims.Role));
            });
            return services;
        }

        /// <summary>True when the request is for the web client area (its pages and endpoints).</summary>
        public static bool IsClientPath(PathString path) => path.StartsWithSegments(ClientAuth.BasePath, StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Answers 404 for the web client when it is off, and sets the security headers of its pages: a strict CSP (no
        /// inline script or style), no sniffing, no framing, no referrer and no caching. The same for the share links
        /// (<c>/shares</c>, #70), which are 404 also while <see cref="ServerSettings.Shares"/> does not allow them, and have
        /// a rate limit per client address. Put it before the admin gate.
        /// </summary>
        public static IApplicationBuilder UseWebClient(this IApplicationBuilder app)
        {
            var options = app.ApplicationServices.GetRequiredService<IOptions<WebClientOptions>>().Value;
            var enabled = options.Enabled;
            var logger = app.ApplicationServices.GetRequiredService<ILoggerFactory>().CreateLogger("FxSshSftpServer.WebClient");
            logger.LogInformation(enabled
                ? "The web client for SFTP users is on at /client."
                : "The web client for SFTP users is off. Set WebClient:Enabled to true to offer it at /client.");

            var shares = app.ApplicationServices.GetRequiredService<ShareAccess>();
            var limiter = app.ApplicationServices.GetRequiredService<ShareRateLimiter>();
            return app.Use(async (HttpContext context, Func<Task> next) =>
            {
                var isShare = ShareAccess.IsSharePath(context.Request.Path);
                if (!isShare && !IsClientPath(context.Request.Path))
                {
                    await next();
                    return;
                }
                if (!enabled || (isShare && !shares.Enabled))
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }
                if (isShare && !limiter.TryAcquire(context.Connection.RemoteIpAddress?.ToString()))
                {
                    context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                    context.Response.Headers.RetryAfter = "60";
                    return;
                }
                if (!context.Request.IsHttps && !options.AllowInsecureHttp && !IsLocal(context.Connection.RemoteIpAddress))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    context.Response.ContentType = "text/plain; charset=utf-8";
                    await context.Response.WriteAsync("The web client needs HTTPS. Use the https:// address of this server.");
                    return;
                }
                var headers = context.Response.Headers;
                headers.ContentSecurityPolicy = ContentSecurityPolicy;
                headers.XContentTypeOptions = "nosniff";
                headers.XFrameOptions = "DENY";
                headers["Referrer-Policy"] = "no-referrer";
                headers.CacheControl = "no-store";
                await next();
            });
        }

        /// <summary>True for a request from this host (loopback), or without a network client (the test server).</summary>
        private static bool IsLocal(System.Net.IPAddress address) => address == null || System.Net.IPAddress.IsLoopback(SshServer.Interfaces.Net.CidrNotation.Normalize(address));

        public static IEndpointRouteBuilder MapWebClient(this IEndpointRouteBuilder endpoints)
        {
            endpoints.MapClientApi();
            endpoints.MapShareApi();
            return endpoints;
        }

        private static async Task ValidatePrincipalAsync(CookieValidatePrincipalContext context)
        {
            var services = context.HttpContext.RequestServices;
            var sessions = services.GetRequiredService<ClientSessions>();
            var name = context.Principal?.Identity?.Name;
            if (ClientClaims.Session(context.Principal) is { } session && name != null && sessions.Touch(session, name))
            {
                var user = services.GetRequiredService<ISettingsRepository>().GetUser(name);
                var now = services.GetRequiredService<TimeProvider>().GetUtcNow().UtcDateTime;
                if (user != null && ClientClaims.Stamp(user) == context.Principal.FindFirst(ClientClaims.StampClaim)?.Value
                    && !UserLoginRules.IsExpired(user, now))
                {
                    return;
                }
                sessions.End(session);
            }

            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(ClientAuth.Scheme);
        }

        private static bool IsApi(HttpRequest request) => request.Path.StartsWithSegments(ClientAuth.ApiPath, StringComparison.OrdinalIgnoreCase);

        private static Task RedirectToLoginAsync(RedirectContext<CookieAuthenticationOptions> context)
        {
            if (IsApi(context.Request))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            }
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        }

        private static Task AccessDeniedAsync(RedirectContext<CookieAuthenticationOptions> context)
        {
            if (IsApi(context.Request))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            }
            // The only refusal of a signed-in user: the password must be changed first.
            context.Response.Redirect(ClientClaims.MustChangePassword(context.HttpContext.User) ? "/client/changepassword" : ClientAuth.LoginPath);
            return Task.CompletedTask;
        }
    }

    /// <summary>Ends the idle web client and share sessions and aborts the idle uploads, once a minute.</summary>
    public sealed class ClientSessionSweeper : BackgroundService
    {
        private readonly ClientSessions _sessions;
        private readonly UploadSessions _uploads;
        private readonly ShareSessions _shares;
        private readonly TimeProvider _time;
        private readonly bool _enabled;
        private readonly ILogger<ClientSessionSweeper> _logger;

        public ClientSessionSweeper(ClientSessions sessions, UploadSessions uploads, ShareSessions shares, TimeProvider time,
            IOptions<WebClientOptions> options, ILogger<ClientSessionSweeper> logger)
        {
            _sessions = sessions;
            _shares = shares;
            _uploads = uploads;
            _time = time;
            _enabled = options.Value.Enabled;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            if (!_enabled)
                return;
            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1), _time);
            try
            {
                while (await timer.WaitForNextTickAsync(stoppingToken))
                {
                    try
                    {
                        _sessions.Sweep();
                        _shares.Sweep();
                        await _uploads.SweepAsync();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "The idle web client sessions could not be ended.");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // stopping
            }
        }
    }
}
