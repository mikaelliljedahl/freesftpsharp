using FreeSftpSharp.Tests.Infrastructure;
using FxSshSftpServer.Security.Oidc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Renci.SshNet;
using Renci.SshNet.Common;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServerModule.Authentication;

namespace FreeSftpSharp.Tests.Oidc;

/// <summary>
/// The SFTP server with the authentication of the web host: the providers (#64) and the ownership rule of the OpenID
/// Connect sign-in (<see cref="OidcSignInSetup.AddOidcSignIn"/>, #145), without an OIDC section.
/// </summary>
public sealed class OidcOwnershipServerFixture : SftpServerFixture
{
    private ServiceProvider? _services;

    protected override IUserAuthenticator? CreateAuthenticator(ISettingsRepository repository)
    {
        _services?.Dispose();
        var configuration = new ConfigurationBuilder().Build();
        var services = new ServiceCollection().AddLogging().AddSingleton(repository);
        services.AddSshServerAuthentication(configuration);
        services.AddOidcSignIn(configuration);
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

/// <summary>
/// A user of the web client sign-in (provider <c>oidc</c>, #145) logs in over SFTP with its stored SSH public key or an
/// app password: the identity provider owns only the password.
/// </summary>
public sealed class OidcOtherProtocolsTests : IClassFixture<OidcOwnershipServerFixture>
{
    private readonly OidcOwnershipServerFixture _server;

    public OidcOtherProtocolsTests(OidcOwnershipServerFixture server)
    {
        _server = server;
    }

    private string AddOidcUser(string name, Action<User> change)
    {
        var root = Path.Combine(_server.TempDirectory, name);
        Directory.CreateDirectory(root);
        var user = new User { Username = name, AuthenticationProvider = OidcClaims.ProviderName, HashedPassword = null, UserRootDirectory = root };
        change(user);
        Assert.True(_server.Repository.AddUser(user));
        return root;
    }

    [Fact]
    public void An_oidc_user_logs_in_with_its_stored_key_but_not_with_a_password()
    {
        var key = TestUserKeys.Ed25519();
        var other = TestUserKeys.Ed25519();
        var root = AddOidcUser("sso-key", u => u.PublicKeys = [key.Entry]);

        using (var client = new SftpClient(SftpServerFixture.Host, _server.Port, "sso-key", key.ToPrivateKeyFile()))
        {
            client.Connect();
            client.WriteAllText("/from-key.txt", "key login");
        }
        Assert.Equal("key login", File.ReadAllText(Path.Combine(root, "from-key.txt")));

        using (var client = new SftpClient(SftpServerFixture.Host, _server.Port, "sso-key", other.ToPrivateKeyFile()))
            Assert.Throws<SshAuthenticationException>(() => client.Connect());
        using (var client = new SftpClient(SftpServerFixture.Host, _server.Port, "sso-key", TestCredentials.Password))
            Assert.Throws<SshAuthenticationException>(() => client.Connect());

        // The login changes nothing of the account: it still belongs to the sign-in.
        Assert.Equal(OidcClaims.ProviderName, _server.Repository.GetUser("sso-key")!.AuthenticationProvider);
    }

    [Fact]
    public void An_oidc_user_logs_in_over_SFTP_with_an_app_password()
    {
        var (entry, secret) = AppPasswordGenerator.Create("sync", UserProtocols.Sftp, DateTime.UtcNow, null);
        AddOidcUser("sso-app", u => u.AppPasswords = [entry]);

        using var client = new SftpClient(SftpServerFixture.Host, _server.Port, "sso-app", secret);
        client.Connect();
        Assert.True(client.IsConnected);
    }
}
