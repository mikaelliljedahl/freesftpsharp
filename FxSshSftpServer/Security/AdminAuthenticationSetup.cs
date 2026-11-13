using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FxSshSftpServer.Security
{
    /// <summary>
    /// Cookie authentication for the admin UI with one local admin account from configuration.
    /// Every endpoint (pages, the Blazor hub) needs an authenticated user unless it allows anonymous access.
    /// </summary>
    public static class AdminAuthenticationSetup
    {
        public const string CookieName = ".FxSshSftpServer.Admin";
        public const string BlazorHubPath = "/_blazor";

        public static IServiceCollection AddAdminAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            services.Configure<AdminAuthOptions>(configuration.GetSection(AdminAuthOptions.SectionName));
            services.AddSingleton<AdminCredentialValidator>();
            services.AddSingleton(TimeProvider.System);
            services.AddSingleton(sp =>
            {
                var options = sp.GetRequiredService<IOptions<AdminAuthOptions>>().Value;
                return new LoginThrottle(sp.GetRequiredService<TimeProvider>(),
                    Math.Max(1, options.MaxFailedLogins), TimeSpan.FromMinutes(Math.Max(1, options.LockoutMinutes)));
            });

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.Cookie.Name = CookieName;
                    options.Cookie.HttpOnly = true;
                    options.Cookie.SameSite = SameSiteMode.Strict;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                    options.LoginPath = "/Login";
                    options.LogoutPath = "/Logout";
                    options.AccessDeniedPath = "/Login";
                    options.ExpireTimeSpan = TimeSpan.FromHours(8);
                    options.SlidingExpiration = true;
                    options.Events = new CookieAuthenticationEvents
                    {
                        // The Blazor hub is not a page: answer 401/403 instead of redirecting to the login page.
                        OnRedirectToLogin = context => RedirectOrStatus(context, StatusCodes.Status401Unauthorized),
                        OnRedirectToAccessDenied = context => RedirectOrStatus(context, StatusCodes.Status403Forbidden),
                    };
                });

            services.AddAuthorization(options =>
            {
                options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
            });

            return services;
        }

        /// <summary>
        /// Closes the whole UI with 503 when no admin credential is configured. Put it first in the pipeline.
        /// </summary>
        public static IApplicationBuilder UseAdminUiRequiresCredential(this IApplicationBuilder app)
        {
            var validator = app.ApplicationServices.GetRequiredService<AdminCredentialValidator>();
            var options = app.ApplicationServices.GetRequiredService<IOptions<AdminAuthOptions>>().Value;
            var logger = app.ApplicationServices.GetRequiredService<ILoggerFactory>().CreateLogger("FxSshSftpServer.AdminAuth");

            if (validator.IsConfigured)
            {
                logger.LogInformation("Admin UI login is enabled for user {UserName}.", validator.UserName);
                return app;
            }

            logger.LogError(
                "The admin UI is closed: {Reason}. Set AdminAuth:UserName and AdminAuth:PasswordHash " +
                "(create the hash with 'FxSshSftpServer {Switch}') and restart. The SSH server still runs.",
                string.IsNullOrWhiteSpace(options.PasswordHash) ? "AdminAuth:PasswordHash is not set"
                    : !AdminPasswordHasher.IsWellFormed(options.PasswordHash) ? "AdminAuth:PasswordHash is not a valid PBKDF2-SHA256 hash"
                    : "AdminAuth:UserName is not set",
                AdminPasswordCommand.Switch);

            return app.Use(async (HttpContext context, Func<Task> _) =>
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                context.Response.ContentType = "text/plain; charset=utf-8";
                await context.Response.WriteAsync(
                    "The admin UI is closed because no admin credential is configured.\n\n" +
                    $"Run 'FxSshSftpServer {AdminPasswordCommand.Switch}' to create a password hash, set " +
                    "AdminAuth:UserName and AdminAuth:PasswordHash (appsettings.json, environment variables " +
                    "AdminAuth__UserName / AdminAuth__PasswordHash, or user secrets) and restart the server.\n");
            });
        }

        private static Task RedirectOrStatus(Microsoft.AspNetCore.Authentication.RedirectContext<CookieAuthenticationOptions> context, int statusCode)
        {
            if (context.Request.Path.StartsWithSegments(BlazorHubPath))
            {
                context.Response.StatusCode = statusCode;
                return Task.CompletedTask;
            }

            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        }
    }
}
