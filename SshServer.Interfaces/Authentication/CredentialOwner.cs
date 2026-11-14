namespace SshServer.Interfaces.Authentication;

/// <summary>The credentials of an account that its owner (<see cref="User.AuthenticationProvider"/>) checks.</summary>
[Flags]
public enum OwnedCredentials
{
    None = 0,

    /// <summary>The password of the account.</summary>
    Password = 1,

    /// <summary>The SSH public keys of the account.</summary>
    PublicKeys = 2,

    All = Password | PublicKeys,
}

/// <summary>
/// The ownership rule of the users of one authentication provider (#145). By default the owner of a user
/// (<see cref="User.AuthenticationProvider"/>) checks all its credentials (#64): a directory such as LDAP checks the
/// password and the keys, and a key stored here is not used. An owner that is registered with this record checks only
/// <see cref="Owns"/>; the other credentials are local credentials of the account, checked by the database provider
/// like those of a local user. Example: the OpenID Connect sign-in (<c>oidc</c>, <see cref="OwnedCredentials.Password"/>):
/// the identity provider owns the password, and the stored SSH public keys of its users are used. The app passwords
/// (<see cref="User.AppPasswords"/>) are always local, for every owner.
/// </summary>
/// <param name="Name">The name of the owner, the value of <see cref="User.AuthenticationProvider"/>.</param>
/// <param name="Owns">The credentials that the owner checks; the others are local.</param>
public sealed record CredentialOwner(string Name, OwnedCredentials Owns)
{
    /// <summary>
    /// True when <paramref name="credential"/> of a user of <paramref name="provider"/> is checked locally: a local user
    /// (null), or an owner in <paramref name="owners"/> that does not own the credential.
    /// </summary>
    public static bool IsLocal(string? provider, OwnedCredentials credential, IEnumerable<CredentialOwner> owners)
    {
        ArgumentNullException.ThrowIfNull(owners);
        if (string.IsNullOrWhiteSpace(provider))
            return true;
        var owner = owners.FirstOrDefault(o => string.Equals(o.Name, provider, StringComparison.Ordinal));
        return owner != null && (owner.Owns & credential) == OwnedCredentials.None;
    }
}
