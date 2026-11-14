using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Security;

namespace SshServer.Authentication.Ldap;

/// <summary>
/// The LDAP / Active Directory provider (issue #64), section <c>Auth:Ldap</c>. Off while <see cref="Server"/> is empty.
/// </summary>
public sealed class LdapAuthenticationOptions
{
    public const string SectionName = "Auth:Ldap";
    public const string UsernamePlaceholder = "{username}";
    public const string DnPlaceholder = "{dn}";
    public const int DefaultTimeoutSeconds = 10;

    /// <summary>The host name of the directory server, for example ldap.example.com.</summary>
    public string? Server { get; set; }

    /// <summary>The port. 0: 636 with <see cref="UseTls"/>, else 389.</summary>
    public int Port { get; set; }

    /// <summary>LDAPS: TLS from the start (port 636).</summary>
    public bool UseTls { get; set; }

    /// <summary>StartTLS on the plain port before the bind.</summary>
    public bool StartTls { get; set; }

    /// <summary>
    /// Allows a connection without TLS: the passwords go over the network in clear text. Only for a test directory on
    /// the same machine or a trusted network.
    /// </summary>
    public bool AllowPlainText { get; set; }

    /// <summary>The account that searches the users (search and bind), for example cn=sftp,ou=services,dc=example,dc=org. Empty: an anonymous search.</summary>
    public string? BindDn { get; set; }

    /// <summary>The password of <see cref="BindDn"/>. Put it in an environment variable or the user secrets.</summary>
    [Secret]
    public string? BindPassword { get; set; }

    /// <summary>Where the users are searched, for example ou=users,dc=example,dc=org.</summary>
    public string? BaseDn { get; set; }

    /// <summary>The search filter of a user; <c>{username}</c> is replaced by the escaped user name (RFC 4515).</summary>
    public string UserFilter { get; set; } = "(&(objectClass=person)(uid={username}))";

    /// <summary>
    /// A direct bind without a search: the DN of a user, for example uid={username},ou=users,dc=example,dc=org (the name is
    /// escaped, RFC 4514). Empty: search and bind with <see cref="UserFilter"/>.
    /// </summary>
    public string? UserDnTemplate { get; set; }

    /// <summary>The attribute of the user entry with the DNs of its groups (Active Directory and the memberOf overlay of OpenLDAP). Empty: not read.</summary>
    public string? GroupAttribute { get; set; } = "memberOf";

    /// <summary>
    /// A search for the groups of the user, for a directory without memberOf, for example
    /// (&amp;(objectClass=groupOfNames)(member={dn})). <c>{dn}</c> and <c>{username}</c> are replaced (escaped). Empty: no search.
    /// </summary>
    public string? GroupSearchFilter { get; set; }

    /// <summary>Where the groups are searched. Empty: <see cref="BaseDn"/>.</summary>
    public string? GroupSearchBaseDn { get; set; }

    /// <summary>
    /// The local group (#61) of a directory group: the key is the DN of the group or its name (the value of its first RDN,
    /// for example "sftp-staff" of cn=sftp-staff,ou=groups,...), the value the name of the local group. Empty: a directory
    /// group gives the local group with the same name. A group without a local group is skipped.
    /// </summary>
    public Dictionary<string, string> GroupMappings { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The local primary group of every user of the directory: the template (storage with %username%, permissions). Empty:
    /// the first mapped group.
    /// </summary>
    public string? DefaultGroup { get; set; }

    /// <summary>The attribute with the OpenSSH public keys of the user (for example sshPublicKey). Empty: no key logins through the directory.</summary>
    public string? SshPublicKeyAttribute { get; set; }

    /// <summary>The time of one directory operation, 1 to 60 seconds.</summary>
    public int TimeoutSeconds { get; set; } = DefaultTimeoutSeconds;

    public bool Enabled => !string.IsNullOrWhiteSpace(Server);

    public int EffectivePort => Port > 0 ? Port : UseTls ? 636 : 389;

    public static void Bind(LdapAuthenticationOptions options, IConfiguration configuration) =>
        configuration.GetSection(SectionName).Bind(options);
}

public sealed class LdapAuthenticationOptionsValidator : IValidateOptions<LdapAuthenticationOptions>
{
    public ValidateOptionsResult Validate(string? name, LdapAuthenticationOptions o)
    {
        var s = LdapAuthenticationOptions.SectionName;
        var errors = new List<string>();
        if (!o.Enabled)
            errors.Add($"{s}:Server is required.");
        if (o.Port is < 0 or > 65535)
            errors.Add($"{s}:Port must be 0 to 65535.");
        if (o.UseTls && o.StartTls)
            errors.Add($"{s}: set UseTls (LDAPS) or StartTls, not both.");
        if (!o.UseTls && !o.StartTls && !o.AllowPlainText)
            errors.Add($"{s}: set UseTls or StartTls; the passwords must not go over the network in clear text (AllowPlainText=true only for a test directory).");
        if (string.IsNullOrWhiteSpace(o.UserDnTemplate))
        {
            if (string.IsNullOrWhiteSpace(o.BaseDn))
                errors.Add($"{s}:BaseDn is required for the user search (or set UserDnTemplate).");
            if (!o.UserFilter.Contains(LdapAuthenticationOptions.UsernamePlaceholder, StringComparison.Ordinal))
                errors.Add($"{s}:UserFilter must contain {LdapAuthenticationOptions.UsernamePlaceholder}.");
        }
        else if (!o.UserDnTemplate.Contains(LdapAuthenticationOptions.UsernamePlaceholder, StringComparison.Ordinal))
            errors.Add($"{s}:UserDnTemplate must contain {LdapAuthenticationOptions.UsernamePlaceholder}.");
        if (!string.IsNullOrWhiteSpace(o.BindDn) && string.IsNullOrEmpty(o.BindPassword))
            errors.Add($"{s}:BindPassword is required with BindDn.");
        if (!string.IsNullOrWhiteSpace(o.GroupSearchFilter))
        {
            if (!o.GroupSearchFilter.Contains(LdapAuthenticationOptions.DnPlaceholder, StringComparison.Ordinal)
                && !o.GroupSearchFilter.Contains(LdapAuthenticationOptions.UsernamePlaceholder, StringComparison.Ordinal))
                errors.Add($"{s}:GroupSearchFilter must contain {LdapAuthenticationOptions.DnPlaceholder} or {LdapAuthenticationOptions.UsernamePlaceholder}.");
            if (string.IsNullOrWhiteSpace(o.GroupSearchBaseDn) && string.IsNullOrWhiteSpace(o.BaseDn))
                errors.Add($"{s}:GroupSearchBaseDn (or BaseDn) is required for the group search.");
        }
        if (o.TimeoutSeconds is < 1 or > 60)
            errors.Add($"{s}:TimeoutSeconds must be 1 to 60.");
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
