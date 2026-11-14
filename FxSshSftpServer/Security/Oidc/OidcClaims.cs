#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;

namespace FxSshSftpServer.Security.Oidc
{
    /// <summary>
    /// Reads the claims of an OpenID Connect sign-in (#73). The handler keeps the claim names of the token
    /// (<c>MapInboundClaims</c> is off), so <c>preferred_username</c> stays <c>preferred_username</c>. A claim name with a
    /// dot is a path into a JSON claim: <c>realm_access.roles</c> reads <c>{"roles": [...]}</c> of <c>realm_access</c>.
    /// </summary>
    public static class OidcClaims
    {
        /// <summary>The claim of the local login cookie that tells which sign-in made it (the scheme name), for the logout at the provider.</summary>
        public const string IdentityProviderClaim = "freesftpsharp:idp";

        /// <summary>The value of <see cref="SshServer.Interfaces.User.AuthenticationProvider"/> of the users that the sign-in creates.</summary>
        public const string ProviderName = "oidc";

        /// <summary>The <c>AuthEvent.Method</c> of a sign-in.</summary>
        public const string Method = "oidc";

        /// <summary>The local user name: the first non-empty value of <paramref name="claim"/>, trimmed; null without one.</summary>
        public static string? Username(ClaimsPrincipal principal, string claim) =>
            Values(principal, claim).Select(v => v.Trim()).FirstOrDefault(v => v.Length > 0);

        /// <summary>
        /// Every value of a claim: the claims with the name (an array in the token is one claim per value), a claim whose
        /// value is a JSON array, or the path into a JSON object. Empty when the token does not have it.
        /// </summary>
        public static IReadOnlyList<string> Values(ClaimsPrincipal principal, string? claim)
        {
            ArgumentNullException.ThrowIfNull(principal);
            if (string.IsNullOrWhiteSpace(claim))
                return [];
            claim = claim.Trim();

            var direct = principal.FindAll(claim).ToList();
            if (direct.Count > 0)
                return direct.SelectMany(c => Expand(c.Value)).ToList();

            var dot = claim.IndexOf('.');
            if (dot <= 0 || dot == claim.Length - 1)
                return [];
            var root = principal.FindFirst(claim[..dot]);
            if (root == null)
                return [];
            try
            {
                using var document = JsonDocument.Parse(root.Value);
                var element = document.RootElement;
                foreach (var part in claim[(dot + 1)..].Split('.'))
                {
                    if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(part, out element))
                        return [];
                }
                return FromJson(element);
            }
            catch (JsonException)
            {
                return [];
            }
        }

        /// <summary>True when <paramref name="options"/> needs no role, or the role claim has the required value (compared with case).</summary>
        public static bool HasRequiredRole(ClaimsPrincipal principal, OidcSignInOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            if (string.IsNullOrWhiteSpace(options.RequiredRoleValue))
                return true;
            return Values(principal, options.RoleClaim).Contains(options.RequiredRoleValue.Trim(), StringComparer.Ordinal);
        }

        /// <summary>
        /// The local groups of the account: each value of <see cref="ClientOidcOptions.GroupsClaim"/> through
        /// <see cref="ClientOidcOptions.GroupMap"/> (without a map: the same name; a Keycloak path <c>/staff</c> is
        /// <c>staff</c>). Null when the groups are not mapped; empty when the account has none.
        /// </summary>
        public static IReadOnlyList<string>? Groups(ClaimsPrincipal principal, ClientOidcOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            if (string.IsNullOrWhiteSpace(options.GroupsClaim))
                return null;
            var groups = new List<string>();
            foreach (var value in Values(principal, options.GroupsClaim))
            {
                var name = value.Trim();
                if (options.GroupMap.Count > 0)
                {
                    if (options.GroupMap.TryGetValue(name, out var mapped) && !string.IsNullOrWhiteSpace(mapped))
                        groups.Add(mapped.Trim());
                    continue;
                }
                name = name.TrimStart('/');
                if (name.Length > 0)
                    groups.Add(name);
            }
            return groups.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        private static IEnumerable<string> Expand(string value)
        {
            var text = value?.Trim() ?? "";
            if (text.StartsWith('['))
            {
                try
                {
                    using var document = JsonDocument.Parse(text);
                    return FromJson(document.RootElement);
                }
                catch (JsonException)
                {
                    // not JSON: the value itself
                }
            }
            return text.Length == 0 ? [] : [text];
        }

        private static IReadOnlyList<string> FromJson(JsonElement element) => element.ValueKind switch
        {
            JsonValueKind.Array => element.EnumerateArray()
                .Where(e => e.ValueKind is JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
                .Select(e => e.ValueKind == JsonValueKind.String ? e.GetString()! : e.GetRawText())
                .Where(v => v.Length > 0)
                .ToList(),
            JsonValueKind.String => element.GetString() is { Length: > 0 } s ? [s] : [],
            JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => [element.GetRawText()],
            _ => [],
        };
    }
}
