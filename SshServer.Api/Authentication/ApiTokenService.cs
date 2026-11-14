using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SshServer.Administration;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Api;

namespace SshServer.Api.Authentication;

/// <summary>A bearer token for an administrator.</summary>
public sealed record ApiToken(string AccessToken, string TokenType, DateTimeOffset ExpiresAt, int ExpiresIn);

/// <summary>
/// Issues the bearer tokens (JWT, HMAC-SHA256) of the REST API. The signing key is made at the first use and stored in
/// the settings database (<see cref="IApiSigningKeyStore"/>), encrypted with the data protection keys of the host, so
/// every node that shares the database and the key ring accepts the tokens. A token has the same claims as the login
/// cookie of the admin UI (<see cref="AdminClaims"/>), and the bearer handler checks its stamp against the stored
/// administrator on every request: a change of the password, permissions, scope or status ends every token at once.
/// </summary>
public sealed class ApiTokenService
{
    private const string Purpose = "FreeSftpSharp.Api.SigningKey.v1";

    private readonly IApiSigningKeyStore _store;
    private readonly IDataProtector _protector;
    private readonly ApiOptions _options;
    private readonly TimeProvider _time;
    private readonly Lazy<SymmetricSecurityKey> _signingKey;

    public ApiTokenService(IApiSigningKeyStore store, IDataProtectionProvider dataProtection, IOptions<ApiOptions> options, TimeProvider time)
    {
        _store = store;
        _protector = dataProtection.CreateProtector(Purpose);
        _options = options.Value;
        _time = time;
        _signingKey = new Lazy<SymmetricSecurityKey>(LoadSigningKey, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public TimeSpan Lifetime => TimeSpan.FromMinutes(_options.TokenLifetimeMinutes);

    /// <summary>The key that signs and checks the tokens.</summary>
    public SecurityKey SigningKey => _signingKey.Value;

    /// <summary>A token for the administrator, valid from <paramref name="issuedAt"/> (now when null) for <see cref="Lifetime"/>.</summary>
    public ApiToken Issue(Admin admin, DateTimeOffset? issuedAt = null)
    {
        var now = issuedAt ?? _time.GetUtcNow();
        var expires = now + Lifetime;
        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            [JwtRegisteredClaimNames.Sub] = admin.Username,
        };
        foreach (var claim in AdminClaims.CreateClaims(admin))
        {
            if (claim.Type == ClaimTypes.Role)
                continue;
            claims[claim.Type == ClaimTypes.Name ? ApiAuthentication.NameClaim : claim.Type] = claim.Value;
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = ApiAuthentication.Issuer,
            Audience = ApiAuthentication.Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            Claims = claims,
            SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.HmacSha256),
        };
        var token = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(descriptor);
        return new ApiToken(token, "Bearer", expires, (int)Lifetime.TotalSeconds);
    }

    /// <summary>The checks of a token, except the stamp (the bearer handler checks it against the database).</summary>
    public TokenValidationParameters ValidationParameters() => new()
    {
        ValidIssuer = ApiAuthentication.Issuer,
        ValidAudience = ApiAuthentication.Audience,
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        IssuerSigningKeyResolver = (_, _, _, _) => [SigningKey],
        NameClaimType = ApiAuthentication.NameClaim,
        ClockSkew = TimeSpan.FromSeconds(30),
        RequireExpirationTime = true,
    };

    private SymmetricSecurityKey LoadSigningKey()
    {
        // Once per process, at the first token: the store is the local settings database.
        var stored = _store.GetOrAddAsync(() => _protector.Protect(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))), CancellationToken.None)
            .GetAwaiter().GetResult();
        try
        {
            return new SymmetricSecurityKey(Convert.FromBase64String(_protector.Unprotect(stored)));
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException(
                "The signing key of the API tokens cannot be decrypted. Are the data protection keys (DataProtection:KeysPath) the same as when it was made?", ex);
        }
    }
}
