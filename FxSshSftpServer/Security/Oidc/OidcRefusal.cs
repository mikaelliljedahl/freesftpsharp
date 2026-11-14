#nullable enable
namespace FxSshSftpServer.Security.Oidc
{
    /// <summary>Why an OpenID Connect sign-in was refused. The login page shows <see cref="OidcRefusalText.Message"/>; the log and the audit event have the reason.</summary>
    public enum OidcRefusal
    {
        None,

        /// <summary>The address is refused by the global IP rules or the auto-ban.</summary>
        AddressRefused,

        /// <summary>The token has no value in the user name claim.</summary>
        NoUsername,

        /// <summary>The role claim does not have the required value.</summary>
        MissingRole,

        /// <summary>No local account has the name, and accounts are not created.</summary>
        UnknownAccount,

        /// <summary>The local account belongs to another authentication provider (#64), or it cannot be created.</summary>
        AccountNotUsable,

        /// <summary>The local account may not sign in now: disabled, expired, another network, no web protocol, no permission.</summary>
        AccountRefused,

        /// <summary>The user has the maximum number of sessions open.</summary>
        TooManySessions,

        /// <summary>The provider or the protocol failed (an error answer, a wrong state, an invalid token).</summary>
        ProviderFailed,
    }

    /// <summary>The texts and the query values of <see cref="OidcRefusal"/>.</summary>
    public static class OidcRefusalText
    {
        /// <summary>The query parameter of the login page.</summary>
        public const string QueryName = "oidc_error";

        public static string Code(OidcRefusal refusal) => refusal.ToString().ToLowerInvariant();

        public static OidcRefusal Parse(string? code)
        {
            foreach (var value in System.Enum.GetValues<OidcRefusal>())
            {
                if (value != OidcRefusal.None && string.Equals(Code(value), code, System.StringComparison.Ordinal))
                    return value;
            }
            return OidcRefusal.None;
        }

        /// <summary>The text for the person at the login page. It does not tell which local rule refused the account.</summary>
        public static string? Message(OidcRefusal refusal, string providerName) => refusal switch
        {
            OidcRefusal.None => null,
            OidcRefusal.MissingRole => $"Your account at {providerName} does not have the role that is needed here. Ask your administrator for access.",
            OidcRefusal.UnknownAccount => $"Your account at {providerName} has no account on this server. Ask your administrator for access.",
            OidcRefusal.NoUsername => $"{providerName} did not send a user name. Ask your administrator to check the sign-in settings.",
            OidcRefusal.TooManySessions => WebClient.ClientLoginFlow.TooManySessionsMessage,
            OidcRefusal.ProviderFailed => $"The sign-in with {providerName} did not complete. Try again.",
            _ => $"Your account at {providerName} cannot sign in here. Ask your administrator for access.",
        };
    }

    /// <summary>The outcome of the account check of a sign-in.</summary>
    public sealed record OidcAccountResult<T>(T? Account, OidcRefusal Refusal, string? Reason) where T : class
    {
        public static OidcAccountResult<T> Ok(T account) => new(account, OidcRefusal.None, null);

        public static OidcAccountResult<T> Refused(OidcRefusal refusal, string reason) => new(null, refusal, reason);
    }
}
