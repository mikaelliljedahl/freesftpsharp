using System.Text.RegularExpressions;
using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SshServer.Authentication.Ldap;
using SshServer.Interfaces.Authentication;

namespace FreeSftpSharp.Tests.Authentication;

/// <summary>
/// An in-memory directory for the LDAP provider: entries with a password, simple binds, and searches by the
/// <c>(uid=...)</c> or <c>(member=...)</c> part of a filter. It keeps the binds and the filters.
/// </summary>
internal sealed class FakeLdapDirectory : ILdapConnector
{
    public sealed record Entry(string Dn, string? Password, Dictionary<string, List<string>> Attributes);

    public List<Entry> Entries { get; } = new();
    public List<(string Dn, bool Ok)> Binds { get; } = new();
    public List<string> Filters { get; } = new();
    public Exception? ConnectError { get; set; }

    public Entry Add(string dn, string? password, params (string Name, string Value)[] attributes)
    {
        var entry = new Entry(dn, password, attributes.GroupBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Select(a => a.Value).ToList(), StringComparer.OrdinalIgnoreCase));
        Entries.Add(entry);
        return entry;
    }

    public ILdapSession Connect() => ConnectError != null ? throw ConnectError : new Session(this);

    private static string Unescape(string value) =>
        Regex.Replace(value, @"\\([0-9a-fA-F]{2})", m => ((char)Convert.ToByte(m.Groups[1].Value, 16)).ToString());

    private sealed class Session(FakeLdapDirectory directory) : ILdapSession
    {
        public bool Bind(string dn, string password)
        {
            var ok = directory.Entries.Any(e => string.Equals(e.Dn, dn, StringComparison.OrdinalIgnoreCase) && e.Password != null && e.Password == password);
            directory.Binds.Add((dn, ok));
            return ok;
        }

        public IReadOnlyList<LdapEntry> Search(string baseDn, string filter, bool subtree, IReadOnlyList<string> attributes)
        {
            directory.Filters.Add(filter);
            IEnumerable<Entry> found;
            if (!subtree)
                found = directory.Entries.Where(e => string.Equals(e.Dn, baseDn, StringComparison.OrdinalIgnoreCase));
            else
            {
                var under = directory.Entries.Where(e => e.Dn.EndsWith(baseDn, StringComparison.OrdinalIgnoreCase));
                var uid = Regex.Match(filter, @"\(uid=([^)]*)\)");
                var member = Regex.Match(filter, @"\(member=([^)]*)\)");
                if (uid.Success)
                    found = under.Where(e => e.Attributes.TryGetValue("uid", out var v) && v.Contains(Unescape(uid.Groups[1].Value)));
                else if (member.Success)
                    found = under.Where(e => e.Attributes.TryGetValue("member", out var v) && v.Contains(Unescape(member.Groups[1].Value), StringComparer.OrdinalIgnoreCase));
                else
                    found = [];
            }
            return found.Select(e => new LdapEntry(e.Dn, e.Attributes
                    .Where(a => attributes.Contains(a.Key, StringComparer.OrdinalIgnoreCase))
                    .ToDictionary(a => a.Key, a => (IReadOnlyList<string>)a.Value)))
                .ToList();
        }

        public void Dispose()
        {
        }
    }
}

/// <summary>The LDAP provider (issue #64) with a fake directory: search and bind, direct bind, groups, keys, refusals.</summary>
public sealed class LdapAuthenticationProviderTests
{
    private const string Base = "ou=users,dc=example,dc=org";
    private const string AliceDn = "uid=alice,ou=users,dc=example,dc=org";
    private readonly FakeLdapDirectory _directory = new();

    public LdapAuthenticationProviderTests()
    {
        _directory.Add("cn=search,dc=example,dc=org", "search-password");
        _directory.Add(AliceDn, "alice-password", ("uid", "alice"),
            ("memberOf", "cn=sftp-staff,ou=groups,dc=example,dc=org"), ("memberOf", "cn=Other,ou=groups,dc=example,dc=org"));
    }

    private LdapAuthenticationProvider Provider(Action<LdapAuthenticationOptions>? configure = null)
    {
        var options = new LdapAuthenticationOptions
        {
            Server = "ldap.example.org", StartTls = true, BindDn = "cn=search,dc=example,dc=org", BindPassword = "search-password", BaseDn = Base,
            UserFilter = "(&(objectClass=person)(uid={username}))",
        };
        configure?.Invoke(options);
        Assert.True(new LdapAuthenticationOptionsValidator().Validate(null, options).Succeeded);
        return new LdapAuthenticationProvider(_directory, Options.Create(options), NullLogger<LdapAuthenticationProvider>.Instance);
    }

    private static AuthRequest Password(string username, string password) => new()
    {
        Username = username, Method = AuthMethods.Password, Password = password, Protocol = "SSH",
    };

    [Fact]
    public async Task Search_and_bind_accepts_the_directory_password_and_maps_the_groups()
    {
        var provider = Provider(o =>
        {
            o.GroupMappings["sftp-staff"] = "staff";
            o.GroupMappings["cn=Other,ou=groups,dc=example,dc=org"] = "readers";
            o.DefaultGroup = "template";
        });

        var result = await provider.AuthenticateAsync(Password("alice", "alice-password"), TestContext.Current.CancellationToken);

        Assert.Equal(AuthOutcome.Success, result.Outcome);
        Assert.Equal("template", result.User!.PrimaryGroup);
        Assert.Equal(["staff", "readers"], result.User.Groups);
        Assert.Contains((AliceDn, true), _directory.Binds);
    }

    [Fact]
    public async Task Without_mappings_a_directory_group_gives_the_local_group_with_its_name()
    {
        var result = await Provider().AuthenticateAsync(Password("alice", "alice-password"), TestContext.Current.CancellationToken);

        Assert.Equal("sftp-staff", result.User!.PrimaryGroup);
        Assert.Equal(["Other"], result.User.Groups);
    }

    [Fact]
    public async Task A_wrong_password_fails()
    {
        var result = await Provider().AuthenticateAsync(Password("alice", "wrong"), TestContext.Current.CancellationToken);

        Assert.Equal(AuthOutcome.Failure, result.Outcome);
        Assert.Equal("wrong password", result.Reason);
    }

    [Fact]
    public async Task An_empty_password_never_reaches_the_directory()
    {
        var result = await Provider().AuthenticateAsync(Password("alice", ""), TestContext.Current.CancellationToken);

        Assert.Equal(AuthOutcome.Failure, result.Outcome);
        Assert.Empty(_directory.Binds);
    }

    [Fact]
    public async Task A_user_that_is_not_in_the_directory_is_not_handled()
    {
        var result = await Provider().AuthenticateAsync(Password("bob", "x"), TestContext.Current.CancellationToken);

        Assert.Equal(AuthOutcome.NotHandled, result.Outcome);
    }

    [Fact]
    public async Task The_user_name_is_escaped_in_the_filter()
    {
        var result = await Provider().AuthenticateAsync(Password("*)(uid=alice", "alice-password"), TestContext.Current.CancellationToken);

        Assert.Equal(AuthOutcome.NotHandled, result.Outcome);
        Assert.Contains(@"(uid=\2a\29\28uid=alice)", _directory.Filters[0]);
    }

    [Fact]
    public async Task Two_entries_for_one_name_refuse()
    {
        _directory.Add("uid=alice,ou=other,ou=users,dc=example,dc=org", "alice-password", ("uid", "alice"));

        var result = await Provider().AuthenticateAsync(Password("alice", "alice-password"), TestContext.Current.CancellationToken);

        Assert.Equal(AuthOutcome.Failure, result.Outcome);
    }

    [Fact]
    public async Task A_wrong_search_account_refuses_and_says_why()
    {
        var provider = Provider(o => o.BindPassword = "not-the-search-password");

        var result = await provider.AuthenticateAsync(Password("alice", "alice-password"), TestContext.Current.CancellationToken);

        Assert.Equal(AuthOutcome.Failure, result.Outcome);
        Assert.Contains("search account", result.Reason);
    }

    [Fact]
    public async Task A_directory_that_cannot_be_reached_refuses()
    {
        _directory.ConnectError = new LdapDirectoryException("connection refused");

        var result = await Provider().AuthenticateAsync(Password("alice", "alice-password"), TestContext.Current.CancellationToken);

        Assert.Equal(AuthOutcome.Failure, result.Outcome);
        Assert.Contains("connection refused", result.Reason);
    }

    [Fact]
    public async Task A_direct_bind_with_the_dn_template_reads_the_groups_as_the_user()
    {
        var provider = Provider(o =>
        {
            o.BindDn = null;
            o.BindPassword = null;
            o.UserDnTemplate = "uid={username},ou=users,dc=example,dc=org";
        });

        var result = await provider.AuthenticateAsync(Password("alice", "alice-password"), TestContext.Current.CancellationToken);

        Assert.Equal(AuthOutcome.Success, result.Outcome);
        Assert.Equal("sftp-staff", result.User!.PrimaryGroup);
        Assert.Equal([(AliceDn, true)], _directory.Binds);
    }

    [Fact]
    public async Task The_dn_template_escapes_the_name()
    {
        var provider = Provider(o =>
        {
            o.BindDn = null;
            o.BindPassword = null;
            o.UserDnTemplate = "uid={username},ou=users,dc=example,dc=org";
        });

        await provider.AuthenticateAsync(Password("alice,ou=admins", "x"), TestContext.Current.CancellationToken);

        Assert.Equal(@"uid=alice\,ou\=admins,ou=users,dc=example,dc=org", _directory.Binds.Single().Dn);
    }

    [Fact]
    public async Task A_group_search_finds_the_groups_of_a_directory_without_memberOf()
    {
        _directory.Add("cn=uploaders,ou=groups,dc=example,dc=org", null, ("member", AliceDn));
        var provider = Provider(o =>
        {
            o.GroupAttribute = null;
            o.GroupSearchBaseDn = "ou=groups,dc=example,dc=org";
            o.GroupSearchFilter = "(&(objectClass=groupOfNames)(member={dn}))";
        });

        var result = await provider.AuthenticateAsync(Password("alice", "alice-password"), TestContext.Current.CancellationToken);

        Assert.Equal("uploaders", result.User!.PrimaryGroup);
        Assert.Empty(result.User.Groups!);
    }

    [Fact]
    public async Task A_public_key_of_the_directory_is_accepted_and_another_refused()
    {
        var key = TestUserKeys.Ed25519();
        _directory.Entries.Single(e => e.Dn == AliceDn).Attributes["sshPublicKey"] = [key.AuthorizedKeysLine];
        var provider = Provider(o => o.SshPublicKeyAttribute = "sshPublicKey");
        AuthRequest Key(byte[] blob) => new() { Username = "alice", Method = AuthMethods.PublicKey, PublicKey = blob, Protocol = "SSH" };

        var ok = await provider.AuthenticateAsync(Key(key.Blob), TestContext.Current.CancellationToken);
        var other = await provider.AuthenticateAsync(Key(TestUserKeys.Ed25519().Blob), TestContext.Current.CancellationToken);

        Assert.Equal(AuthOutcome.Success, ok.Outcome);
        Assert.Equal(AuthOutcome.Failure, other.Outcome);
        Assert.DoesNotContain(_directory.Binds, b => b.Dn == AliceDn); // no password, no user bind
    }

    [Fact]
    public async Task Without_a_key_attribute_a_public_key_is_not_handled()
    {
        var result = await Provider().AuthenticateAsync(
            new AuthRequest { Username = "alice", Method = AuthMethods.PublicKey, PublicKey = TestUserKeys.Ed25519().Blob, Protocol = "SSH" },
            TestContext.Current.CancellationToken);

        Assert.Equal(AuthOutcome.NotHandled, result.Outcome);
        Assert.Empty(_directory.Binds);
    }

    [Theory]
    [InlineData("alice*", @"alice\2a")]
    [InlineData(@"a\b", @"a\5cb")]
    [InlineData("é", @"\c3\a9")]
    public void Filter_values_are_escaped(string value, string expected) => Assert.Equal(expected, LdapEscape.FilterValue(value));

    [Theory]
    [InlineData("cn=staff,ou=groups,dc=example,dc=org", "staff")]
    [InlineData(@"cn=a\,b,ou=groups", "a,b")]
    [InlineData("CN=Domain Users,CN=Users,DC=corp", "Domain Users")]
    public void The_name_of_a_group_is_its_first_rdn_value(string dn, string expected) => Assert.Equal(expected, LdapEscape.FirstRdnValue(dn));

    [Fact]
    public void Plain_text_needs_an_explicit_setting()
    {
        var options = new LdapAuthenticationOptions { Server = "ldap.example.org", BaseDn = Base };
        Assert.True(new LdapAuthenticationOptionsValidator().Validate(null, options).Failed);
        options.AllowPlainText = true;
        Assert.True(new LdapAuthenticationOptionsValidator().Validate(null, options).Succeeded);
        options.UseTls = true;
        options.StartTls = true;
        Assert.True(new LdapAuthenticationOptionsValidator().Validate(null, options).Failed);
    }
}
