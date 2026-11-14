using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using SshServer.Administration;

namespace SshServer.Api.Authentication;

/// <summary>
/// The authentication of the REST API: a bearer token (JWT, <see cref="BearerScheme"/>) from <c>POST /api/v1/token</c>, or
/// an API key in the <see cref="ApiKeyHeader"/> header (<see cref="ApiKeyScheme"/>). The policy scheme <see cref="Scheme"/>
/// selects one of them per request. The login cookie of the admin UI is never used for the API, so a browser session
/// cannot be used for cross-site requests to it.
/// </summary>
public static class ApiAuthentication
{
    /// <summary>The policy scheme of the API routes: the API key scheme when the header is there, else the bearer scheme.</summary>
    public const string Scheme = "Api";

    public const string BearerScheme = "ApiBearer";

    public const string ApiKeyScheme = "ApiKey";

    public const string ApiKeyHeader = "X-API-Key";

    /// <summary>The authorization policy of every API route: an administrator signed in with <see cref="Scheme"/>.</summary>
    public const string Policy = "Api";

    public const string Issuer = "FreeSftpSharp";

    public const string Audience = "FreeSftpSharp.Api.v1";

    /// <summary>The claim type of the administrator name in a bearer token.</summary>
    public const string NameClaim = "name";

    internal static string SelectScheme(HttpContext context) =>
        context.Request.Headers.ContainsKey(ApiKeyHeader) ? ApiKeyScheme : BearerScheme;

    /// <summary>True when the request was signed in with an API key (not with a bearer token).</summary>
    public static bool UsesApiKey(ClaimsPrincipal user) => user.HasClaim(c => c.Type == AdminClaims.ApiKeyClaim);
}
