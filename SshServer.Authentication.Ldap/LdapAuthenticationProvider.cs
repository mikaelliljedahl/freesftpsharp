using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Authentication;

namespace SshServer.Authentication.Ldap;

/// <summary>
/// Authentication against an LDAP directory or Active Directory (issue #64). The user is found with a search
/// (<see cref="LdapAuthenticationOptions.UserFilter"/>, as the search account or anonymous) or by its DN
/// (<see cref="LdapAuthenticationOptions.UserDnTemplate"/>); the password is checked with a bind as the user on its own
/// connection, a public key against <see cref="LdapAuthenticationOptions.SshPublicKeyAttribute"/>. The groups of the user
/// (<c>memberOf</c> or a group search) become its local groups (#61) through
/// <see cref="LdapAuthenticationOptions.GroupMappings"/>, with <see cref="LdapAuthenticationOptions.DefaultGroup"/> as the
/// template. A user that is not in the directory is not handled; a directory error refuses the login (fail closed).
/// </summary>
public sealed class LdapAuthenticationProvider : IAuthenticationProvider
{
    public const string ProviderName = "ldap";

    private readonly ILdapConnector _connector;
    private readonly LdapAuthenticationOptions _options;
    private readonly ILogger _logger;

    public LdapAuthenticationProvider(ILdapConnector connector, IOptions<LdapAuthenticationOptions> options, ILogger<LdapAuthenticationProvider> logger)
    {
        _connector = connector;
        _options = options.Value;
        _logger = logger;
    }

    public string Name => ProviderName;

    public async ValueTask<AuthResult> AuthenticateAsync(AuthRequest request, CancellationToken ct)
    {
        if (request.Password == null && (request.PublicKey == null || string.IsNullOrWhiteSpace(_options.SshPublicKeyAttribute)))
            return AuthResult.NotHandled;
        // An empty password is an "unauthenticated bind" (RFC 4513 section 5.1.2), which many servers accept.
        if (request.Password is { Length: 0 })
            return AuthResult.Failure("empty password");

        // The client library is synchronous: run it on the thread pool with a deadline of its own.
        var work = Task.Run(() => Authenticate(request), ct);
        try
        {
            return await work.WaitAsync(TimeSpan.FromSeconds(_options.TimeoutSeconds * 2), ct);
        }
        catch (TimeoutException)
        {
            _logger.LogWarning("The directory did not answer the {Request} in time; the login is refused.", request);
            return AuthResult.Failure("the directory did not answer in time");
        }
        catch (LdapDirectoryException ex)
        {
            _logger.LogWarning("The directory cannot check the {Request}: {Error}", request, ex.Message);
            return AuthResult.Failure("the directory cannot be used: " + ex.Message);
        }
    }

    private AuthResult Authenticate(AuthRequest request)
    {
        using var search = _connector.Connect();
        var searchBound = false;
        if (!string.IsNullOrWhiteSpace(_options.BindDn))
        {
            if (!search.Bind(_options.BindDn, _options.BindPassword ?? ""))
                throw new LdapDirectoryException("the search account cannot bind (wrong BindDn or BindPassword)");
            searchBound = true;
        }

        var attributes = Attributes();
        LdapEntry? entry;
        string dn;
        if (!string.IsNullOrWhiteSpace(_options.UserDnTemplate))
        {
            dn = _options.UserDnTemplate.Replace(LdapAuthenticationOptions.UsernamePlaceholder, LdapEscape.DnValue(request.Username), StringComparison.Ordinal);
            entry = searchBound ? ReadEntry(search, dn, attributes) : null;
            if (searchBound && entry == null)
                return AuthResult.NotHandled;
        }
        else
        {
            var filter = _options.UserFilter.Replace(LdapAuthenticationOptions.UsernamePlaceholder, LdapEscape.FilterValue(request.Username), StringComparison.Ordinal);
            var entries = search.Search(_options.BaseDn!, filter, subtree: true, attributes);
            if (entries.Count == 0)
                return AuthResult.NotHandled;
            if (entries.Count > 1)
                return AuthResult.Failure("the user name matches more than one entry of the directory");
            entry = entries[0];
            dn = entry.DistinguishedName;
        }

        ILdapSession? userSession = null;
        try
        {
            if (request.Password != null)
            {
                userSession = _connector.Connect();
                if (!userSession.Bind(dn, request.Password))
                    return AuthResult.Failure("wrong password");
                // A direct bind without a search account: read the entry as the user.
                entry ??= ReadEntry(userSession, dn, attributes);
            }
            else
            {
                entry ??= ReadEntry(search, dn, attributes);
                if (entry == null)
                    return AuthResult.NotHandled;
                if (!HasKey(entry, request.PublicKey!))
                    return AuthResult.Failure("the public key is not accepted");
            }

            var groups = GroupsOf(entry, dn, request.Username, searchBound ? search : userSession ?? search);
            return AuthResult.Success(ToUser(groups));
        }
        finally
        {
            userSession?.Dispose();
        }
    }

    private List<string> Attributes()
    {
        var attributes = new List<string>();
        if (!string.IsNullOrWhiteSpace(_options.GroupAttribute))
            attributes.Add(_options.GroupAttribute);
        if (!string.IsNullOrWhiteSpace(_options.SshPublicKeyAttribute))
            attributes.Add(_options.SshPublicKeyAttribute);
        if (attributes.Count == 0)
            attributes.Add("1.1"); // RFC 4511 section 4.5.1.8: no attributes
        return attributes;
    }

    private static LdapEntry? ReadEntry(ILdapSession session, string dn, IReadOnlyList<string> attributes) =>
        session.Search(dn, "(objectClass=*)", subtree: false, attributes).FirstOrDefault();

    private bool HasKey(LdapEntry entry, byte[] blob)
    {
        var match = false;
        foreach (var line in entry.Values(_options.SshPublicKeyAttribute))
        {
            try
            {
                if (SshPublicKey.Parse(line, PublicKeySource.Admin, DateTime.UtcNow).Matches(blob))
                    match = true;
            }
            catch (PublicKeyFormatException)
            {
                // A value that is not a supported key is skipped.
            }
        }
        return match;
    }

    /// <summary>The DNs of the groups of the user: its group attribute and the group search.</summary>
    private List<string> GroupsOf(LdapEntry? entry, string dn, string username, ILdapSession session)
    {
        var groups = new List<string>();
        if (entry != null)
            groups.AddRange(entry.Values(_options.GroupAttribute));
        if (!string.IsNullOrWhiteSpace(_options.GroupSearchFilter))
        {
            var filter = _options.GroupSearchFilter
                .Replace(LdapAuthenticationOptions.DnPlaceholder, LdapEscape.FilterValue(dn), StringComparison.Ordinal)
                .Replace(LdapAuthenticationOptions.UsernamePlaceholder, LdapEscape.FilterValue(username), StringComparison.Ordinal);
            var baseDn = string.IsNullOrWhiteSpace(_options.GroupSearchBaseDn) ? _options.BaseDn! : _options.GroupSearchBaseDn;
            groups.AddRange(session.Search(baseDn, filter, subtree: true, ["1.1"]).Select(g => g.DistinguishedName));
        }
        return groups.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>The local groups of the directory groups, with the default group as the primary group.</summary>
    internal ExternalUser ToUser(IReadOnlyList<string> groupDns)
    {
        var local = new List<string>();
        foreach (var groupDn in groupDns)
        {
            var name = LdapEscape.FirstRdnValue(groupDn);
            string? mapped;
            if (_options.GroupMappings.Count == 0)
                mapped = name;
            else if (!_options.GroupMappings.TryGetValue(groupDn.Trim(), out mapped) && (name == null || !_options.GroupMappings.TryGetValue(name, out mapped)))
                mapped = null;
            if (!string.IsNullOrWhiteSpace(mapped) && !local.Contains(mapped, StringComparer.OrdinalIgnoreCase))
                local.Add(mapped);
        }

        var primary = !string.IsNullOrWhiteSpace(_options.DefaultGroup) ? _options.DefaultGroup : local.FirstOrDefault() ?? "";
        return new ExternalUser
        {
            PrimaryGroup = primary,
            Groups = local.Where(g => !string.Equals(g, primary, StringComparison.OrdinalIgnoreCase)).ToList(),
        };
    }
}
