#nullable enable
using System;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace FxSshSftpServer.Security.Oidc
{
    /// <summary>
    /// Checks the <c>logout_token</c> of an OpenID Connect Back-Channel Logout 1.0 request (#145) for one sign-in scheme:
    /// a JWT signed with a key of the discovery document of the provider (the same keys as the id_tokens; <c>none</c> is
    /// refused), the issuer of the discovery document, the client id of the scheme as audience, <c>iat</c>, the lifetime
    /// when it has <c>exp</c>, the <c>events</c> claim with the back-channel logout event, a <c>sid</c> or a <c>sub</c>,
    /// and no <c>nonce</c> (so an id_token is never a logout token). A <c>typ</c> header must be <c>logout+jwt</c> or
    /// <c>JWT</c>.
    /// </summary>
    public sealed class OidcLogoutTokenValidator
    {
        public const string BackChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

        private readonly IOptionsMonitor<OpenIdConnectOptions> _options;
        private readonly JsonWebTokenHandler _handler = new() { MapInboundClaims = false };

        public OidcLogoutTokenValidator(IOptionsMonitor<OpenIdConnectOptions> options)
        {
            _options = options;
        }

        /// <summary>The logout of a valid token, or the reason why it is not valid (for the log; the values are from the client).</summary>
        public async Task<(OidcLogout? Logout, string? Error)> ValidateAsync(string scheme, string? token, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(token))
                return (null, "the request has no logout_token");
            if (token.Length > 16 * 1024)
                return (null, "the logout_token is too long");
            var options = _options.Get(scheme);
            if (options.ConfigurationManager == null)
                return (null, "the sign-in has no configuration");

            var result = await ValidateSignatureAsync(options, token, refresh: false, ct);
            if (result.Exception is SecurityTokenSignatureKeyNotFoundException)
                result = await ValidateSignatureAsync(options, token, refresh: true, ct); // the provider rotated its keys
            if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt)
                return (null, "the logout_token is not valid: " + (result.Exception?.GetType().Name ?? "unknown"));

            if (jwt.TryGetHeaderValue<string>("typ", out var typ) && !string.IsNullOrEmpty(typ)
                && !string.Equals(typ, "logout+jwt", StringComparison.OrdinalIgnoreCase) && !string.Equals(typ, "JWT", StringComparison.OrdinalIgnoreCase))
            {
                return (null, "the logout_token has the type " + typ);
            }

            JsonDocument payload;
            try
            {
                payload = JsonDocument.Parse(Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(jwt.EncodedPayload)));
            }
            catch (Exception ex) when (ex is JsonException or FormatException or ArgumentException)
            {
                return (null, "the payload of the logout_token is not JSON");
            }
            using (payload)
            {
                var root = payload.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                    return (null, "the payload of the logout_token is not an object");
                if (!root.TryGetProperty("iat", out var iat) || iat.ValueKind != JsonValueKind.Number)
                    return (null, "the logout_token has no iat");
                if (root.TryGetProperty("nonce", out _))
                    return (null, "the logout_token has a nonce");
                if (!root.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Object
                    || !events.TryGetProperty(BackChannelLogoutEvent, out var logoutEvent) || logoutEvent.ValueKind != JsonValueKind.Object)
                {
                    return (null, "the logout_token has no back-channel logout event");
                }
                var sid = Text(root, "sid");
                var sub = Text(root, "sub");
                if (sid == null && sub == null)
                    return (null, "the logout_token has neither sid nor sub");
                return (new OidcLogout(jwt.Issuer, sid, sub), null);
            }
        }

        private async Task<TokenValidationResult> ValidateSignatureAsync(OpenIdConnectOptions options, string token, bool refresh, CancellationToken ct)
        {
            if (refresh)
                options.ConfigurationManager!.RequestRefresh();
            var configuration = await options.ConfigurationManager!.GetConfigurationAsync(ct);
            return await _handler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidIssuer = configuration.Issuer,
                ValidAudience = options.ClientId,
                IssuerSigningKeys = configuration.SigningKeys,
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                RequireExpirationTime = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(2),
            });
        }

        private static string? Text(JsonElement root, string name) =>
            root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())
                ? value.GetString()
                : null;
    }
}
