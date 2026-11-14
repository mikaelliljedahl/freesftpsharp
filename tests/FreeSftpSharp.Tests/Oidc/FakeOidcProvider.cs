using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace FreeSftpSharp.Tests.Oidc;

/// <summary>
/// A minimal OpenID Connect provider in memory for the sign-in tests (#73): the discovery document, the keys (a generated
/// RSA key as JWKS), the authorize endpoint (answers with the <c>form_post</c> page of a code for <see cref="SignedIn"/>),
/// the token endpoint (checks the client, the redirect URI and PKCE S256, and issues a signed id_token with the nonce)
/// and the end session endpoint. It is the backchannel of the handler and the "browser side" of the tests.
/// </summary>
public sealed partial class FakeOidcProvider : HttpMessageHandler
{
    public const string Issuer = "https://idp.test";

    private readonly RsaSecurityKey _key;
    private readonly ConcurrentDictionary<string, PendingCode> _codes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string?> _clients = new(StringComparer.Ordinal);

    public FakeOidcProvider()
    {
        _key = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "test-key-" + Guid.NewGuid().ToString("N")[..8] };
    }

    /// <summary>The claims of the account that is signed in at the provider; the next authorize request issues a code for it.</summary>
    public Dictionary<string, object> SignedIn { get; set; } = new();

    /// <summary>Publish an end_session_endpoint in the discovery document.</summary>
    public bool PublishEndSession { get; set; } = true;

    /// <summary>The requests of the authorize endpoint (their query), for the checks of the tests.</summary>
    public ConcurrentQueue<Dictionary<string, string>> AuthorizeRequests { get; } = new();

    public ConcurrentQueue<Dictionary<string, string>> TokenRequests { get; } = new();

    public ConcurrentQueue<Uri> EndSessionRequests { get; } = new();

    /// <summary>Registers a client of the provider; a null secret is a public client.</summary>
    public FakeOidcProvider WithClient(string clientId, string? secret)
    {
        _clients[clientId] = secret;
        return this;
    }

    /// <summary>The claims of a signed-in account with a user name, roles and groups, and the session id <paramref name="sid"/> (#145).</summary>
    public void SignIn(string username, string[]? roles = null, string[]? groups = null, string? sid = null)
    {
        var claims = new Dictionary<string, object> { ["sub"] = "sub-" + username, ["preferred_username"] = username };
        if (sid != null)
            claims["sid"] = sid;
        if (roles != null)
            claims["roles"] = roles;
        if (groups != null)
            claims["groups"] = groups;
        SignedIn = claims;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath;
        return path switch
        {
            "/.well-known/openid-configuration" => Json(Discovery()),
            "/jwks" => Json(new { keys = new[] { Jwk() } }),
            "/authorize" => Authorize(Query(request.RequestUri)),
            "/token" when request.Method == HttpMethod.Post => Token(await Form(request, cancellationToken), request),
            "/logout" => EndSession(request.RequestUri),
            _ => new HttpResponseMessage(HttpStatusCode.NotFound),
        };
    }

    private object Discovery()
    {
        var document = new Dictionary<string, object>
        {
            ["issuer"] = Issuer,
            ["authorization_endpoint"] = Issuer + "/authorize",
            ["token_endpoint"] = Issuer + "/token",
            ["jwks_uri"] = Issuer + "/jwks",
            ["response_types_supported"] = new[] { "code" },
            ["response_modes_supported"] = new[] { "query", "form_post" },
            ["subject_types_supported"] = new[] { "public" },
            ["id_token_signing_alg_values_supported"] = new[] { "RS256" },
            ["code_challenge_methods_supported"] = new[] { "S256" },
        };
        if (PublishEndSession)
            document["end_session_endpoint"] = Issuer + "/logout";
        return document;
    }

    private object Jwk()
    {
        var parameters = _key.Rsa.ExportParameters(false);
        return new
        {
            kty = "RSA",
            use = "sig",
            alg = "RS256",
            kid = _key.KeyId,
            n = Base64UrlEncoder.Encode(parameters.Modulus),
            e = Base64UrlEncoder.Encode(parameters.Exponent),
        };
    }

    private HttpResponseMessage Authorize(Dictionary<string, string> query)
    {
        AuthorizeRequests.Enqueue(query);
        if (!query.TryGetValue("client_id", out var clientId) || !_clients.ContainsKey(clientId)
            || query.GetValueOrDefault("response_type") != "code"
            || query.GetValueOrDefault("code_challenge_method") != "S256" || string.IsNullOrEmpty(query.GetValueOrDefault("code_challenge"))
            || !query.TryGetValue("redirect_uri", out var redirect))
        {
            return new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent("invalid authorize request") };
        }

        var code = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(24));
        _codes[code] = new PendingCode(clientId, redirect, query["code_challenge"], query.GetValueOrDefault("nonce"), new Dictionary<string, object>(SignedIn));
        var html = new StringBuilder()
            .Append("<html><body onload=\"document.forms[0].submit()\"><form method=\"post\" action=\"").Append(WebUtility.HtmlEncode(redirect)).Append("\">")
            .Append("<input type=\"hidden\" name=\"code\" value=\"").Append(WebUtility.HtmlEncode(code)).Append("\" />")
            .Append("<input type=\"hidden\" name=\"state\" value=\"").Append(WebUtility.HtmlEncode(query.GetValueOrDefault("state") ?? "")).Append("\" />")
            .Append("</form></body></html>");
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(html.ToString(), Encoding.UTF8, "text/html") };
    }

    private HttpResponseMessage Token(Dictionary<string, string> form, HttpRequestMessage request)
    {
        TokenRequests.Enqueue(form);
        var (clientId, secret) = ClientCredentials(form, request);
        if (form.GetValueOrDefault("grant_type") != "authorization_code" || clientId == null || !_clients.TryGetValue(clientId, out var expectedSecret)
            || (expectedSecret != null && expectedSecret != secret))
        {
            return Error("invalid_client");
        }
        if (!form.TryGetValue("code", out var code) || !_codes.TryRemove(code, out var pending) || pending.ClientId != clientId
            || pending.RedirectUri != form.GetValueOrDefault("redirect_uri"))
        {
            return Error("invalid_grant");
        }
        var verifier = form.GetValueOrDefault("code_verifier") ?? "";
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        if (challenge != pending.CodeChallenge)
            return Error("invalid_grant");

        var claims = new Dictionary<string, object>(pending.Claims);
        if (pending.Nonce != null)
            claims["nonce"] = pending.Nonce;
        var now = DateTime.UtcNow;
        var idToken = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = clientId,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Claims = claims,
            SigningCredentials = new SigningCredentials(_key, SecurityAlgorithms.RsaSha256),
        });
        return Json(new { access_token = "access-" + Guid.NewGuid().ToString("N"), token_type = "Bearer", expires_in = 300, id_token = idToken });
    }

    /// <summary>
    /// A logout token of OpenID Connect Back-Channel Logout 1.0 (#145) for <paramref name="audience"/>, signed with the key
    /// of the provider (or with another key). <paramref name="change"/> edits the claims before the signature.
    /// </summary>
    public string LogoutToken(string audience, string? sid, string? sub, Action<Dictionary<string, object>>? change = null, bool otherKey = false,
        string issuer = Issuer, string type = "logout+jwt", TimeSpan? age = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["events"] = new Dictionary<string, object> { ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>() },
        };
        if (sid != null)
            claims["sid"] = sid;
        if (sub != null)
            claims["sub"] = sub;
        change?.Invoke(claims);
        var key = otherKey ? new RsaSecurityKey(RSA.Create(2048)) { KeyId = _key.KeyId } : _key;
        var issued = DateTime.UtcNow - (age ?? TimeSpan.Zero);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            IssuedAt = issued,
            NotBefore = issued,
            Expires = issued.AddMinutes(2),
            TokenType = type,
            Claims = claims,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
        });
    }

    /// <summary>An unsigned token (<c>alg: none</c>) with the claims of a valid logout token.</summary>
    public static string UnsignedLogoutToken(string audience, string sid)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var header = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { alg = "none", typ = "logout+jwt" }));
        var payload = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["iss"] = Issuer, ["aud"] = audience, ["iat"] = now, ["exp"] = now + 120, ["jti"] = Guid.NewGuid().ToString("N"), ["sid"] = sid,
            ["events"] = new Dictionary<string, object> { ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>() },
        }));
        return header + "." + payload + ".";
    }

    private HttpResponseMessage EndSession(Uri uri)
    {
        EndSessionRequests.Enqueue(uri);
        var query = Query(uri);
        if (query.TryGetValue("post_logout_redirect_uri", out var back))
        {
            var response = new HttpResponseMessage(HttpStatusCode.Redirect);
            response.Headers.Location = new Uri(back + (back.Contains('?') ? "&" : "?") + "state=" + Uri.EscapeDataString(query.GetValueOrDefault("state") ?? ""));
            return response;
        }
        return new HttpResponseMessage(HttpStatusCode.OK);
    }

    private static (string? Id, string? Secret) ClientCredentials(Dictionary<string, string> form, HttpRequestMessage request)
    {
        if (request.Headers.Authorization is { Scheme: "Basic", Parameter: { } basic })
        {
            var text = Encoding.UTF8.GetString(Convert.FromBase64String(basic));
            var colon = text.IndexOf(':');
            return (Uri.UnescapeDataString(text[..colon]), Uri.UnescapeDataString(text[(colon + 1)..]));
        }
        return (form.GetValueOrDefault("client_id"), form.GetValueOrDefault("client_secret"));
    }

    private static HttpResponseMessage Error(string error) =>
        new(HttpStatusCode.BadRequest) { Content = new StringContent(JsonSerializer.Serialize(new { error }), Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Json(object value) =>
        new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };

    private static async Task<Dictionary<string, string>> Form(HttpRequestMessage request, CancellationToken ct) =>
        ParsePairs(request.Content == null ? "" : await request.Content.ReadAsStringAsync(ct));

    public static Dictionary<string, string> Query(Uri uri) => ParsePairs(uri.Query.TrimStart('?'));

    private static Dictionary<string, string> ParsePairs(string text) =>
        text.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .ToDictionary(p => WebUtility.UrlDecode(p[0]), p => p.Length > 1 ? WebUtility.UrlDecode(p[1]) : "", StringComparer.Ordinal);

    /// <summary>The action and the fields of a <c>form_post</c> page (of this provider or of Keycloak).</summary>
    public static (Uri Action, Dictionary<string, string> Fields) ParseFormPost(string html)
    {
        var action = FormActionRegex().Match(html);
        if (!action.Success)
            throw new InvalidOperationException("The page has no form: " + html);
        var fields = InputRegex().Matches(html).ToDictionary(m => WebUtility.HtmlDecode(m.Groups["name"].Value), m => WebUtility.HtmlDecode(m.Groups["value"].Value),
            StringComparer.Ordinal);
        return (new Uri(WebUtility.HtmlDecode(action.Groups[1].Value)), fields);
    }

    [GeneratedRegex("<form[^>]*action=\"([^\"]+)\"", RegexOptions.IgnoreCase)]
    private static partial Regex FormActionRegex();

    [GeneratedRegex("<input[^>]*type=\"hidden\"[^>]*name=\"(?<name>[^\"]+)\"[^>]*value=\"(?<value>[^\"]*)\"", RegexOptions.IgnoreCase)]
    private static partial Regex InputRegex();

    private sealed record PendingCode(string ClientId, string RedirectUri, string CodeChallenge, string? Nonce, Dictionary<string, object> Claims);
}
