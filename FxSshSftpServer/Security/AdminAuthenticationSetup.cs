using System;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Users;

namespace FxSshSftpServer.Security
{
    /// <summary>
    /// Cookie authentication and authorization for the admin UI. The administrators are stored in the settings database
    /// (<see cref="IAdminStore"/>); the configured <c>AdminAuth</c> account is imported once as the first super admin.
    /// Every endpoint (pages, the Blazor hub) needs an authenticated administrator unless it allows anonymous access,
    /// and each page needs the policy of its permission (<see cref="AdminPolicies"/>).
    /// </summary>
    public static class AdminAuthenticationSetup
    {
        public const string CookieName = ".FxSshSftpServer.Admin";
        public const string BlazorHubPath = "/_blazor";

        public static IServiceCollection AddAdminAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            services.Configure<AdminAuthOptions>(configuration.GetSection(AdminAuthOptions.SectionName));
            services.AddSingleton<AdminCredentialValidator>();
            services.AddSingleton<AdminSessionValidator>();
            services.AddSingleton<AdminLoginFlow>();
            services.AddSingleton<PendingTwoFactorLogin>();
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
                    options.ExpireTimeSpan = TimeSpan.FromHours(8);
                    options.SlidingExpiration = true;
                    options.Events = new CookieAuthenticationEvents
                    {
                        // The Blazor hub is not a page: answer 401 instead of redirecting to the login page.
                        OnRedirectToLogin = context => RedirectOrStatus(context, StatusCodes.Status401Unauthorized),
                        // A logged-in administrator without the permission of a page gets 403, not the login page.
                        OnRedirectToAccessDenied = Forbidden,
                        OnValidatePrincipal = ValidatePrincipalAsync,
                    };
                });

            services.AddAuthorization(options =>
            {
                options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
                options.AddAdminPolicies();
            });

            // The circuit checks its login again periodically; the scoped services check the permissions themselves.
            services.AddScoped<AuthenticationStateProvider, AdminRevalidatingAuthenticationStateProvider>();
            services.AddScoped<CurrentAdmin>();
            // The scoped repository sets the administrator as the actor of the provider events (#134).
            services.TryAddSingleton<SshServer.Interfaces.Audit.AuditActorContext>();
            services.AddScoped<AdminScopedSettingsRepository>();
            services.AddScoped<ScopedAuditLog>();
            services.AddScoped<ScopedConnections>();
            services.AddScoped<TwoFactorAdministration>();
            // In the admin UI every user operation goes through the scope of the signed-in administrator. The command
            // line (ServerConsoleApp) keeps the singleton on the shared repository.
            services.AddScoped(sp => new UserAdministrationService(sp.GetRequiredService<AdminScopedSettingsRepository>()));
            // The virtual folders (#56) too: changing them needs ManageFolders; their users are those in the scope.
            services.AddScoped(sp => new SshServerModule.Storage.VirtualFolderService(sp.GetRequiredService<AdminScopedSettingsRepository>()));
            // The groups (#61): changing them needs ManageGroups; a scoped administrator sees only the groups of its role.
            services.AddScoped(sp => new SshServer.Interfaces.Groups.GroupService(sp.GetRequiredService<AdminScopedSettingsRepository>()));
            // The quota counters (#62): the usage, rescan and reset of the users in the scope (the singletons come with AddSshServerStorage).
            services.AddScoped(sp => new SshServerModule.Quotas.QuotaAdministrationService(sp.GetRequiredService<AdminScopedSettingsRepository>(),
                sp.GetRequiredService<SshServer.Interfaces.Quotas.IEffectiveQuotaService>(), sp.GetRequiredService<SshServerModule.Quotas.QuotaUsageTracker>(),
                sp.GetRequiredService<SshServerModule.Quotas.QuotaScanQueue>()));

            return services;
        }

        /// <summary>
        /// Imports the configured <c>AdminAuth</c> account as the first super admin when no administrator is stored, and
        /// closes the whole UI with 503 when there is still no administrator. Put it first in the pipeline.
        /// </summary>
        public static IApplicationBuilder UseAdminUiRequiresCredential(this IApplicationBuilder app)
        {
            var services = app.ApplicationServices;
            var store = services.GetRequiredService<IAdminStore>();
            var administration = services.GetRequiredService<AdminAdministrationService>();
            var options = services.GetRequiredService<IOptions<AdminAuthOptions>>().Value;
            var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("FxSshSftpServer.AdminAuth");

            // Startup, before the server accepts requests: waiting here is fine.
            var hasAdmins = store.AnyAdminAsync(default).GetAwaiter().GetResult();
            if (!hasAdmins && options.IsConfigured
                && administration.ImportConfiguredAdminAsync(options.UserName, options.PasswordHash, default).GetAwaiter().GetResult())
            {
                // Information, not a warning: the import is the expected first start after an upgrade.
                logger.LogInformation(
                    "Imported the configured admin account {UserName} (AdminAuth) as a super admin into the settings database. " +
                    "Logins now use the stored administrators; manage them on the Admins page. AdminAuth is not read again.",
                    options.UserName.Trim());
                hasAdmins = true;
            }
            else if (hasAdmins && !string.IsNullOrWhiteSpace(options.PasswordHash))
            {
                logger.LogInformation(
                    "AdminAuth is configured, but administrators are stored in the settings database: AdminAuth is ignored.");
            }

            if (hasAdmins)
            {
                logger.LogInformation("Admin UI login is enabled.");
                return app;
            }

            logger.LogError(
                "The admin UI is closed: no administrator is stored and {Reason}. Create one with 'FxSshSftpServer {CreateSwitch} <name>', " +
                "or set AdminAuth:UserName and AdminAuth:PasswordHash (create the hash with 'FxSshSftpServer {Switch}'), and restart. The SSH server still runs.",
                string.IsNullOrWhiteSpace(options.PasswordHash) ? "AdminAuth:PasswordHash is not set"
                    : !PasswordHasher.IsWellFormed(options.PasswordHash) ? "AdminAuth:PasswordHash is not a valid PBKDF2-SHA256 hash"
                    : "AdminAuth:UserName is not set",
                AdminCreateCommand.Switch,
                AdminPasswordCommand.Switch);

            // The web client of the users (#69) does not need an administrator: it and the files of its pages stay open.
            var clientEnabled = services.GetRequiredService<IOptions<WebClient.WebClientOptions>>().Value.Enabled;
            return app.Use(async (HttpContext context, Func<Task> next) =>
            {
                if (clientEnabled && (WebClient.WebClientSetup.IsClientPath(context.Request.Path) || IsStaticFile(context.Request.Path)))
                {
                    await next();
                    return;
                }
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                context.Response.ContentType = "text/plain; charset=utf-8";
                await context.Response.WriteAsync(
                    "The admin UI is closed because no administrator exists.\n\n" +
                    $"Run 'FxSshSftpServer {AdminCreateCommand.Switch} <name>' to create the first administrator, or run " +
                    $"'FxSshSftpServer {AdminPasswordCommand.Switch}' to create a password hash and set " +
                    "AdminAuth:UserName and AdminAuth:PasswordHash (appsettings.json, environment variables " +
                    "AdminAuth__UserName / AdminAuth__PasswordHash, or user secrets). Then restart the server.\n");
            });
        }

        private static bool IsStaticFile(PathString path) =>
            path.StartsWithSegments("/lib") || path.StartsWithSegments("/css") || path.StartsWithSegments("/js");

        private static async Task ValidatePrincipalAsync(CookieValidatePrincipalContext context)
        {
            var validator = context.HttpContext.RequestServices.GetRequiredService<AdminSessionValidator>();
            IPAddress client = context.HttpContext.Connection.RemoteIpAddress;
            if (await validator.IsValidAsync(context.Principal, client, context.HttpContext.RequestAborted))
                return;

            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        private static async Task Forbidden(Microsoft.AspNetCore.Authentication.RedirectContext<CookieAuthenticationOptions> context)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            if (context.Request.Path.StartsWithSegments(BlazorHubPath))
                return;
            context.Response.ContentType = "text/html; charset=utf-8";
            await context.Response.WriteAsync(
                "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\" /><title>Access denied - FreeSftpSharp</title>" +
                "<link rel=\"stylesheet\" href=\"/lib/bootstrap/css/bootstrap.min.css\" /></head>" +
                "<body class=\"p-4\"><h1 class=\"h4\">Access denied</h1><p>You do not have the permission for this page.</p>" +
                "<p><a href=\"/\">Back to the dashboard</a></p></body></html>");
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
