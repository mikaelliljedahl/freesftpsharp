namespace SshServer.Authentication.Ldap;

/// <summary>Opens connections to the directory. The real one is <see cref="ProtocolsLdapConnector"/>; the tests use a fake.</summary>
public interface ILdapConnector
{
    ILdapSession Connect();
}

/// <summary>One connection to the directory (synchronous, like the LDAP client library).</summary>
public interface ILdapSession : IDisposable
{
    /// <summary>A simple bind. False for wrong credentials (LDAP result 49); throws <see cref="LdapDirectoryException"/> for other errors.</summary>
    bool Bind(string dn, string password);

    /// <summary>A search; an empty list when the base does not exist. Throws <see cref="LdapDirectoryException"/> for errors.</summary>
    IReadOnlyList<LdapEntry> Search(string baseDn, string filter, bool subtree, IReadOnlyList<string> attributes);
}

/// <summary>One entry of a search: its DN and the values of the asked attributes (names without case).</summary>
public sealed class LdapEntry
{
    public LdapEntry(string distinguishedName, IReadOnlyDictionary<string, IReadOnlyList<string>> attributes)
    {
        DistinguishedName = distinguishedName;
        Attributes = new Dictionary<string, IReadOnlyList<string>>(attributes, StringComparer.OrdinalIgnoreCase);
    }

    public string DistinguishedName { get; }

    public IReadOnlyDictionary<string, IReadOnlyList<string>> Attributes { get; }

    public IReadOnlyList<string> Values(string? attribute) =>
        attribute != null && Attributes.TryGetValue(attribute, out var values) ? values : [];
}

/// <summary>The directory could not be used (connection, TLS, timeout, rights). The message has no password.</summary>
public sealed class LdapDirectoryException : Exception
{
    public LdapDirectoryException(string message, Exception? inner = null) : base(message, inner)
    {
    }
}

/// <summary>Escaping of user input in filters (RFC 4515) and DNs (RFC 4514), so a user name cannot change a query.</summary>
public static class LdapEscape
{
    public static string FilterValue(string value)
    {
        var builder = new System.Text.StringBuilder(value.Length);
        foreach (var b in System.Text.Encoding.UTF8.GetBytes(value))
        {
            var c = (char)b;
            if (b >= 0x80 || c is '\\' or '*' or '(' or ')' or '\0')
                builder.Append('\\').Append(b.ToString("x2"));
            else
                builder.Append(c);
        }
        return builder.ToString();
    }

    public static string DnValue(string value)
    {
        var builder = new System.Text.StringBuilder(value.Length + 8);
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            if (c is ',' or '+' or '"' or '\\' or '<' or '>' or ';' or '=' || (c == '#' && i == 0) || (c == ' ' && (i == 0 || i == value.Length - 1)))
                builder.Append('\\').Append(c);
            else if (c == '\0')
                builder.Append("\\00");
            else
                builder.Append(c);
        }
        return builder.ToString();
    }

    /// <summary>The value of the first RDN of a DN ("staff" of "cn=staff,ou=groups,dc=example,dc=org"), unescaped, or null.</summary>
    public static string? FirstRdnValue(string dn)
    {
        var equals = dn.IndexOf('=');
        if (equals < 0)
            return null;
        var builder = new System.Text.StringBuilder();
        for (var i = equals + 1; i < dn.Length; i++)
        {
            var c = dn[i];
            if (c == '\\' && i + 1 < dn.Length)
            {
                builder.Append(dn[++i]);
                continue;
            }
            if (c is ',' or '+')
                break;
            builder.Append(c);
        }
        var result = builder.ToString().Trim();
        return result.Length == 0 ? null : result;
    }
}
