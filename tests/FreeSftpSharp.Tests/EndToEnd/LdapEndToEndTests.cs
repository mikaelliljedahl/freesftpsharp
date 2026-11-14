using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Renci.SshNet.Common;
using SshServer.Authentication.Ldap;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Groups;
using SshServerModule.Authentication;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// The OpenLDAP directory of the LDAP tests (#64): FREESFTPSHARP_TEST_LDAP is host:port of a bitnamilegacy/openldap
/// container started with LDAP_ROOT=dc=example,dc=org, LDAP_ADMIN_PASSWORD=adminpassword, LDAP_USERS=alice,bob,
/// LDAP_PASSWORDS=alice-password,bob-password and LDAP_GROUP=sftp-staff (see .github/workflows/build.yml). Without it the
/// tests are skipped.
/// </summary>
internal static class LdapTestServer
{
    public const string Variable = "FREESFTPSHARP_TEST_LDAP";

    public static string? Address => string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(Variable)) ? null : Environment.GetEnvironmentVariable(Variable)!.Trim();

    public static void SkipIfUnavailable()
    {
        if (Address == null)
            Assert.Skip($"{Variable} is not set (an OpenLDAP test directory is needed).");
    }

    public static IConfiguration Configuration(string externalRoot)
    {
        var parts = Address!.Split(':');
        return new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Auth:Ldap:Server"] = parts[0],
            ["Auth:Ldap:Port"] = parts.Length > 1 ? parts[1] : "389",
            ["Auth:Ldap:AllowPlainText"] = "true", // a container on this machine
            ["Auth:Ldap:BindDn"] = "cn=admin,dc=example,dc=org",
            ["Auth:Ldap:BindPassword"] = "adminpassword",
            ["Auth:Ldap:BaseDn"] = "ou=users,dc=example,dc=org",
            ["Auth:Ldap:UserFilter"] = "(&(objectClass=inetOrgPerson)(uid={username}))",
            ["Auth:Ldap:GroupAttribute"] = "",
            ["Auth:Ldap:GroupSearchBaseDn"] = "ou=groups,dc=example,dc=org",
            ["Auth:Ldap:GroupSearchFilter"] = "(&(objectClass=groupOfNames)(member={dn}))",
            ["Auth:ExternalUsers:RootDirectory"] = externalRoot,
        }).Build();
    }
}

/// <summary>The SFTP server with the LDAP provider against the test directory (database only without it).</summary>
public sealed class LdapServerFixture : SftpServerFixture
{
    private ServiceProvider? _services;

    protected override IUserAuthenticator? CreateAuthenticator(ISettingsRepository repository)
    {
        if (LdapTestServer.Address == null)
            return null;
        _services?.Dispose();
        var configuration = LdapTestServer.Configuration(Path.Combine(TempDirectory, "ldap-users"));
        var services = new ServiceCollection().AddLogging().AddSingleton(repository);
        services.AddSshServerAuthentication(configuration);
        services.AddLdapAuthentication(configuration);
        _services = services.BuildServiceProvider();
        return _services.GetRequiredService<IUserAuthenticator>();
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        if (_services != null)
            await _services.DisposeAsync();
    }
}

/// <summary>Issue #64: a user of an OpenLDAP directory logs in with SSH.NET and gets the local group of its directory group.</summary>
[Trait("Category", "Ldap")]
public sealed class LdapEndToEndTests : IClassFixture<LdapServerFixture>
{
    private readonly LdapServerFixture _server;

    public LdapEndToEndTests(LdapServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public void A_directory_user_logs_in_with_the_directory_password_and_gets_the_mapped_group()
    {
        LdapTestServer.SkipIfUnavailable();
        if (_server.Repository.GetGroups().All(g => g.Name != "sftp-staff"))
            _server.Repository.AddGroup(new Group { Name = "sftp-staff" });

        using (var client = _server.CreateClient("alice-password", "alice"))
        {
            client.Connect();
            client.WriteAllText("/hello.txt", "from ldap");
        }

        var stored = _server.Repository.GetUser("alice");
        Assert.Equal(LdapAuthenticationProvider.ProviderName, stored.AuthenticationProvider);
        Assert.Equal(_server.Repository.GetGroups().Single(g => g.Name == "sftp-staff").Id, stored.PrimaryGroupId);
        Assert.Null(stored.HashedPassword);
    }

    [Fact]
    public void A_wrong_directory_password_and_an_unknown_name_are_refused()
    {
        LdapTestServer.SkipIfUnavailable();

        using (var client = _server.CreateClient("not-the-password", "bob"))
            Assert.Throws<SshAuthenticationException>(() => client.Connect());
        using (var client = _server.CreateClient("x", "nobody-in-the-directory"))
            Assert.Throws<SshAuthenticationException>(() => client.Connect());

        Assert.Null(_server.Repository.GetUser("nobody-in-the-directory"));
    }

    [Fact]
    public async Task The_real_connector_binds_and_searches_the_directory()
    {
        LdapTestServer.SkipIfUnavailable();
        var options = new LdapAuthenticationOptions();
        LdapAuthenticationOptions.Bind(options, LdapTestServer.Configuration(Path.GetTempPath()));
        var provider = new LdapAuthenticationProvider(new ProtocolsLdapConnector(Options.Create(options)), Options.Create(options),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<LdapAuthenticationProvider>.Instance);

        var ok = await provider.AuthenticateAsync(new AuthRequest { Username = "bob", Method = AuthMethods.Password, Password = "bob-password", Protocol = "SSH" },
            TestContext.Current.CancellationToken);
        var injection = await provider.AuthenticateAsync(new AuthRequest { Username = "*", Method = AuthMethods.Password, Password = "bob-password", Protocol = "SSH" },
            TestContext.Current.CancellationToken);

        Assert.Equal(AuthOutcome.Success, ok.Outcome);
        Assert.Equal("sftp-staff", ok.User!.PrimaryGroup);
        Assert.Equal(AuthOutcome.NotHandled, injection.Outcome);
    }
}
