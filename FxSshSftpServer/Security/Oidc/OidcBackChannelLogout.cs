#nullable enable
using System;
using System.Threading.Tasks;
using FxSsh.SshServerModule.Security;
using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FxSshSftpServer.Security.Oidc
{
    /// <summary>
    /// OpenID Connect Back-Channel Logout 1.0 (#145): the identity provider posts a <c>logout_token</c> to
    /// <see cref="OidcSignInSetup.AdminBackChannelLogoutPath"/> or <see cref="OidcSignInSetup.ClientBackChannelLogoutPath"/>
    /// when a session ends there. A valid token (<see cref="OidcLogoutTokenValidator"/>) ends the local sessions of that
    /// provider session: the web client sessions in <see cref="ClientSessions"/>, the admin login cookies through
    /// <see cref="AdminOidcLogouts"/>. The answer is 200 (also when no session matched) or 400 with
    /// <c>invalid_request</c>, never cached. Mapped only for a configured area.
    /// </summary>
    public static class OidcBackChannelLogout
    {
        public static IEndpointRouteBuilder MapOidcBackChannelLogout(this IEndpointRouteBuilder endpoints)
        {
            var services = endpoints.ServiceProvider;
            var admin = services.GetRequiredService<IOptions<AdminOidcOptions>>().Value;
            var client = services.GetRequiredService<IOptions<ClientOidcOptions>>().Value;
            var clientEnabled = services.GetRequiredService<IOptions<WebClientOptions>>().Value.Enabled;
            if (admin.IsEnabled)
                Map(endpoints, OidcSignInSetup.AdminBackChannelLogoutPath, OidcSignInSetup.AdminScheme, "admin UI",
                    (http, logout) => http.RequestServices.GetRequiredService<AdminOidcLogouts>().Add(logout));
            if (client.IsEnabled && clientEnabled)
                Map(endpoints, OidcSignInSetup.ClientBackChannelLogoutPath, OidcSignInSetup.ClientScheme, "web client",
                    (http, logout) => http.RequestServices.GetRequiredService<ClientSessions>().EndOidc(logout));
            return endpoints;
        }

        private static void Map(IEndpointRouteBuilder endpoints, string path, string scheme, string area, Action<HttpContext, OidcLogout> end)
        {
            endpoints.MapPost(path, async (HttpContext http) =>
                {
                    http.Response.Headers.CacheControl = "no-store";
                    http.Response.Headers.Pragma = "no-cache";
                    var logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("FxSshSftpServer.Oidc");
                    if (!http.Request.HasFormContentType)
                        return Refuse(logger, area, "the request is not a form");
                    var form = await http.Request.ReadFormAsync(http.RequestAborted);
                    var validator = http.RequestServices.GetRequiredService<OidcLogoutTokenValidator>();
                    var (logout, error) = await validator.ValidateAsync(scheme, form["logout_token"], http.RequestAborted);
                    if (logout == null)
                        return Refuse(logger, area, error);
                    end(http, logout);
                    logger.LogInformation("Back-channel logout of the {Area} from {Issuer}: sid {Sid}, sub {Subject}.", area,
                        LogText.Clean(logout.Issuer), LogText.Clean(logout.Sid) ?? "-", LogText.Clean(logout.Subject) ?? "-");
                    return Results.Ok();
                })
                .AllowAnonymous()
                .DisableAntiforgery()
                .ExcludeFromDescription();
        }

        private static IResult Refuse(ILogger logger, string area, string? reason)
        {
            logger.LogWarning("Back-channel logout of the {Area} refused: {Reason}.", area, LogText.Clean(reason));
            return Results.Json(new { error = "invalid_request", error_description = "The logout_token is not valid." }, statusCode: StatusCodes.Status400BadRequest);
        }
    }
}
