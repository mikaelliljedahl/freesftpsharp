using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Api.ApiKeys;

namespace SshServer.Api.Authentication;

/// <summary>Signs in a request with the API key in the <see cref="ApiAuthentication.ApiKeyHeader"/> header (<see cref="ApiKeyService"/>).</summary>
internal sealed class ApiKeyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly ApiKeyService _keys;

    public ApiKeyAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ApiKeyService keys)
        : base(options, logger, encoder)
    {
        _keys = keys;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(ApiAuthentication.ApiKeyHeader, out var values) || string.IsNullOrWhiteSpace(values.ToString()))
            return AuthenticateResult.NoResult();

        var claims = await _keys.AuthenticateAsync(values.ToString().Trim(), Context.Connection.RemoteIpAddress, Context.RequestAborted);
        if (claims == null)
        {
            Logger.LogWarning("Refused an API key from {Client}: unknown, expired, or its administrator is disabled or not allowed from there.",
                Context.Connection.RemoteIpAddress);
            return AuthenticateResult.Fail("The API key is not valid.");
        }

        var principal = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(claims, Scheme.Name));
        return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = "ApiKey";
        return Task.CompletedTask;
    }
}
