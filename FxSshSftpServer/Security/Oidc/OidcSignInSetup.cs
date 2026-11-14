#nullable enable
using System;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using FxSsh.SshServerModule.Security;
using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace FxSshSftpServer.Security.Oidc
{
    /// <summary>
    /// The OpenID Connect sign-in (#73) of the admin UI (<c>Auth:Oidc:Admin</c>, scheme <see cref="AdminScheme"/>) and of
    /// the web client (<c>Auth:Oidc:Client</c>, scheme <see cref="ClientScheme"/>). A handler is registered only for a
    /// section with an <c>Authority</c> (the client one only with <c>WebClient:Enabled</c>), so without configuration
    /// nothing changes. Both use the authorization code flow with PKCE and <c>form_post</c>; the middleware checks the
    /// state and the nonce. The tokens are not kept: the handler signs in to the local cookie scheme of its area
    /// (the admin cookie, or <see cref="ClientAuth.Scheme"/>) with a local principal, so an admin sign-in never opens
    /// <c>/client</c> and a client sign-in never opens the admin UI.
    /// </summary>
    public static class OidcSignInSetup
    {
        public const string AdminScheme = "OidcAdmin";
        public const string ClientScheme = "OidcClient";

        public const string AdminCallbackPath = "/signin-oidc-admin";
        public const string ClientCallbackPath = "/signin-oidc-client";
        public const string AdminSignedOutCallbackPath = "/signout-callback-oidc-admin";
        public const string ClientSignedOutCallbackPath = "/signout-callback-oidc-client";
        public const string AdminRemoteSignOutPath = "/signout-oidc-admin";
        public const string ClientRemoteSignOutPath = "/signout-oidc-client";

        /// <summary>
        /// The pages after a sign-in: they continue with a same-site navigation, so the browser sends the SameSite=Strict
        /// login cookie (it does not on the redirect of the cross-site <c>form_post</c>).
        /// </summary>
        public const string AdminDonePath = "/signin-done";
        public const string ClientDonePath = "/client/signin-done";

        public static IServiceCollection AddOidcSignIn(this IServiceCollection services, IConfiguration configuration)
        {
            ArgumentNullException.ThrowIfNull(configuration);
            services.AddOptions<AdminOidcOptions>().Bind(configuration.GetSection(AdminOidcOptions.SectionName)).ValidateOnStart();
            services.AddOptions<ClientOidcOptions>().Bind(configuration.GetSection(ClientOidcOptions.SectionName)).ValidateOnStart();
            services.AddSingleton<IValidateOptions<AdminOidcOptions>, OidcSignInOptionsValidator>();
            services.AddSingleton<IValidateOptions<ClientOidcOptions>, OidcSignInOptionsValidator>();
            services.AddSingleton<AdminOidcAccounts>();
            services.AddSingleton<IAdminPasswordLoginPolicy, AdminOidcPasswordLoginPolicy>();
            services.AddSingleton<ClientOidcAccounts>();
            // The ownership rule of its users (#145): the identity provider owns the password only; their SSH keys are local.
            services.AddSingleton(new SshServer.Interfaces.Authentication.CredentialOwner(OidcClaims.ProviderName,
                SshServer.Interfaces.Authentication.OwnedCredentials.Password));

            var admin = configuration.GetSection(AdminOidcOptions.SectionName).Get<AdminOidcOptions>() ?? new AdminOidcOptions();
            var client = configuration.GetSection(ClientOidcOptions.SectionName).Get<ClientOidcOptions>() ?? new ClientOidcOptions();
            var clientEnabled = configuration.GetValue<bool>($"{WebClientOptions.SectionName}:{nameof(WebClientOptions.Enabled)}");

            var authentication = services.AddAuthentication();
            if (admin.IsEnabled)
            {
                authentication.AddOpenIdConnect(AdminScheme, admin.DisplayName, o =>
                {
                    Configure(o, admin, AdminCallbackPath, AdminSignedOutCallbackPath, AdminRemoteSignOutPath, CookieAuthenticationDefaults.AuthenticationScheme);
                    o.Events.OnTicketReceived = AdminTicketReceivedAsync;
                    o.Events.OnRemoteFailure = context => RemoteFailureAsync(context, "/Login", "admin UI");
                });
            }
            if (client.IsEnabled && clientEnabled)
            {
                authentication.AddOpenIdConnect(ClientScheme, client.DisplayName, o =>
                {
                    Configure(o, client, ClientCallbackPath, ClientSignedOutCallbackPath, ClientRemoteSignOutPath, ClientAuth.Scheme);
                    o.Events.OnTicketReceived = ClientTicketReceivedAsync;
                    o.Events.OnRemoteFailure = context => RemoteFailureAsync(context, ClientAuth.LoginPath, "web client");
                });
            }
            return services;
        }

        /// <summary>
        /// With <c>DisableLocalLogin</c>: a POST to the password and code pages of that area answers 404 before routing (so
        /// before the antiforgery check of the page). Put it before <c>UseRouting</c>.
        /// </summary>
        public static IApplicationBuilder UseOidcSignIn(this IApplicationBuilder app)
        {
            var services = app.ApplicationServices;
            var admin = services.GetRequiredService<IOptions<AdminOidcOptions>>().Value;
            var client = services.GetRequiredService<IOptions<ClientOidcOptions>>().Value;
            var adminOff = admin.IsEnabled && admin.DisableLocalLogin;
            var clientOff = client.IsEnabled && client.DisableLocalLogin;
            var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("FxSshSftpServer.Oidc");
            if (admin.IsEnabled)
                logger.LogInformation("OpenID Connect sign-in to the admin UI with {Authority}{Local}.", admin.Authority, adminOff ? "; the password login is off" : "");
            if (client.IsEnabled)
                logger.LogInformation("OpenID Connect sign-in to the web client with {Authority}{Local}.", client.Authority, clientOff ? "; the password login is off" : "");
            if (!adminOff && !clientOff)
                return app;

            return app.Use(async (HttpContext context, Func<Task> next) =>
            {
                if (HttpMethods.IsPost(context.Request.Method) && !context.Request.Query.ContainsKey("handler"))
                {
                    var path = context.Request.Path;
                    if ((adminOff && (IsPath(path, "/Login") || IsPath(path, "/LoginCode")))
                        || (clientOff && (IsPath(path, ClientAuth.LoginPath) || IsPath(path, "/client/logincode"))))
                    {
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        return;
                    }
                }
                await next();
            });
        }

        private static bool IsPath(PathString path, string page) =>
            path.Equals(page, StringComparison.OrdinalIgnoreCase) || path.Equals(page + "/", StringComparison.OrdinalIgnoreCase);

        /// <summary>True for the paths of the client sign-in outside <c>/client</c>: they stay open when the admin UI is closed.</summary>
        public static bool IsClientPath(PathString path) =>
            path.StartsWithSegments(ClientCallbackPath) || path.StartsWithSegments(ClientSignedOutCallbackPath) || path.StartsWithSegments(ClientRemoteSignOutPath);

        /// <summary>True when the scheme is registered (its section is configured).</summary>
        public static async Task<bool> IsEnabledAsync(HttpContext context, string scheme) =>
            await context.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>().GetSchemeAsync(scheme) != null;

        /// <summary>True when <paramref name="user"/> signed in with <paramref name="scheme"/>.</summary>
        public static bool SignedInWith(ClaimsPrincipal? user, string scheme) =>
            string.Equals(user?.FindFirstValue(OidcClaims.IdentityProviderClaim), scheme, StringComparison.Ordinal);

        /// <summary>
        /// After the local logout: ends the session at the provider of <paramref name="scheme"/> when it is configured and
        /// publishes an <c>end_session_endpoint</c> (RP-initiated logout). The provider returns to
        /// <paramref name="redirectUri"/>. True when the response is that redirect.
        /// </summary>
        public static async Task<bool> SignOutAtProviderAsync(HttpContext context, string scheme, string redirectUri)
        {
            if (!await IsEnabledAsync(context, scheme))
                return false;
            var options = context.RequestServices.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(scheme);
            try
            {
                var configuration = await options.ConfigurationManager!.GetConfigurationAsync(context.RequestAborted);
                if (string.IsNullOrEmpty(configuration.EndSessionEndpoint))
                    return false;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Logger(context).LogWarning(ex, "The discovery document of {Scheme} cannot be read; the session ends only here.", scheme);
                return false;
            }
            await context.SignOutAsync(scheme, new AuthenticationProperties { RedirectUri = redirectUri });
            return true;
        }

        private static void Configure(OpenIdConnectOptions o, OidcSignInOptions settings, string callbackPath, string signedOutPath, string remoteSignOutPath,
            string signInScheme)
        {
            o.Authority = settings.Authority!.Trim();
            o.ClientId = settings.ClientId!.Trim();
            o.ClientSecret = string.IsNullOrWhiteSpace(settings.ClientSecret) ? null : settings.ClientSecret;
            o.RequireHttpsMetadata = settings.RequireHttpsMetadata;
            o.ResponseType = OpenIdConnectResponseType.Code;
            o.ResponseMode = OpenIdConnectResponseMode.FormPost;
            o.UsePkce = true;
            o.Scope.Clear();
            foreach (var scope in settings.EffectiveScopes())
                o.Scope.Add(scope);
            o.CallbackPath = callbackPath;
            o.SignedOutCallbackPath = signedOutPath;
            o.RemoteSignOutPath = remoteSignOutPath;
            o.SignInScheme = signInScheme;
            o.SignOutScheme = signInScheme;
            // The tokens stay in the handler: the login cookie has only the local claims.
            o.SaveTokens = false;
            o.GetClaimsFromUserInfoEndpoint = false;
            o.MapInboundClaims = false;
            o.TokenValidationParameters.NameClaimType = settings.UsernameClaim;
            o.TokenValidationParameters.RoleClaimType = settings.RoleClaim;
            o.Events = new OpenIdConnectEvents
            {
                // Keycloak needs the client to return to the post_logout_redirect_uri without an id_token_hint (not kept).
                OnRedirectToIdentityProviderForSignOut = context =>
                {
                    context.ProtocolMessage.ClientId = context.Options.ClientId;
                    return Task.CompletedTask;
                },
            };
        }

        private static async Task AdminTicketReceivedAsync(TicketReceivedContext context)
        {
            var http = context.HttpContext;
            var services = http.RequestServices;
            var options = services.GetRequiredService<IOptions<AdminOidcOptions>>().Value;
            var flow = services.GetRequiredService<AdminLoginFlow>();
            var result = await services.GetRequiredService<AdminOidcAccounts>().ResolveAsync(context.Principal!, http.Connection.RemoteIpAddress, http.RequestAborted);
            if (result.Account is not { } admin)
            {
                await flow.PublishFailedAsync(http, OidcClaims.Username(context.Principal!, options.UsernameClaim), OidcClaims.Method, result.Reason);
                Deny(context, "/Login", result.Refusal);
                return;
            }
            context.Principal = await flow.RecordSuccessAsync(http, admin, OidcClaims.Method, AdminScheme);
        }

        private static async Task ClientTicketReceivedAsync(TicketReceivedContext context)
        {
            var http = context.HttpContext;
            var services = http.RequestServices;
            var options = services.GetRequiredService<IOptions<ClientOidcOptions>>().Value;
            var flow = services.GetRequiredService<ClientLoginFlow>();
            var remote = http.Connection.RemoteIpAddress ?? IPAddress.Loopback; // TestServer has no address
            var result = services.GetRequiredService<ClientOidcAccounts>().Resolve(context.Principal!, remote);
            if (result.Account is not { } user)
            {
                await flow.PublishFailedAsync(http, OidcClaims.Username(context.Principal!, options.UsernameClaim), OidcClaims.Method, result.Reason);
                Deny(context, ClientAuth.LoginPath, result.Refusal);
                return;
            }
            var principal = await flow.StartAsync(http, user, OidcClaims.Method, passwordExpired: false, ClientScheme);
            if (principal == null)
            {
                Deny(context, ClientAuth.LoginPath, OidcRefusal.TooManySessions);
                return;
            }
            context.Principal = principal;
        }

        private static Task RemoteFailureAsync(RemoteFailureContext context, string loginPath, string area)
        {
            Logger(context.HttpContext).LogWarning("OpenID Connect sign-in to the {Area} failed: {Message}", area, LogText.Clean(context.Failure?.Message));
            context.Response.Redirect(loginPath + "?" + OidcRefusalText.QueryName + "=" + OidcRefusalText.Code(OidcRefusal.ProviderFailed));
            context.HandleResponse();
            return Task.CompletedTask;
        }

        private static void Deny(TicketReceivedContext context, string loginPath, OidcRefusal refusal)
        {
            context.Response.Redirect(loginPath + "?" + OidcRefusalText.QueryName + "=" + OidcRefusalText.Code(refusal));
            context.HandleResponse();
        }

        private static ILogger Logger(HttpContext context) =>
            context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("FxSshSftpServer.Oidc");
    }

    /// <summary>The password login of the administrators (login page and REST API token) is off with <c>Auth:Oidc:Admin:DisableLocalLogin</c>.</summary>
    public sealed class AdminOidcPasswordLoginPolicy : IAdminPasswordLoginPolicy
    {
        public AdminOidcPasswordLoginPolicy(IOptions<AdminOidcOptions> options)
        {
            var admin = options.Value;
            PasswordLoginAllowed = !(admin.IsEnabled && admin.DisableLocalLogin);
        }

        public bool PasswordLoginAllowed { get; }
    }
}
