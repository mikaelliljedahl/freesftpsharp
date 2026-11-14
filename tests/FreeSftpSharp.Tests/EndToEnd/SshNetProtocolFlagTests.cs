using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet.Common;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>The protocol flags and app passwords of a user (issue #71) at the SFTP login.</summary>
public sealed class SshNetProtocolFlagTests : IClassFixture<SftpServerFixture>
{
    private const string Password = "Correct-Horse-42";
    private readonly SftpServerFixture _server;

    public SshNetProtocolFlagTests(SftpServerFixture server)
    {
        _server = server;
    }

    private string AddUser(UserProtocols protocols, AppPassword? appPassword = null)
    {
        var name = "proto-" + Guid.NewGuid().ToString("N")[..8];
        _server.AddUser(name, PasswordHasher.Hash(Password, PasswordHasher.MinimumIterations));
        var user = _server.Repository.GetUser(name);
        user.AllowedProtocols = protocols;
        user.AppPasswords = appPassword == null ? null : [appPassword];
        _server.Repository.UpdateUser(user);
        return name;
    }

    [Fact]
    public void A_user_without_WebDav_still_logs_in_with_SFTP()
    {
        using var client = _server.CreateClient(Password, AddUser(UserProtocols.Sftp));
        client.Connect();
        Assert.True(client.IsConnected);
    }

    [Fact]
    public void A_user_without_SFTP_is_refused_like_a_wrong_password()
    {
        using var client = _server.CreateClient(Password, AddUser(UserProtocols.WebDav));
        Assert.Throws<SshAuthenticationException>(() => client.Connect());
    }

    [Fact]
    public void An_app_password_for_SFTP_logs_in_and_one_for_WebDav_only_does_not()
    {
        var (sftp, sftpSecret) = AppPasswordGenerator.Create("backup", UserProtocols.Sftp, DateTime.UtcNow, null);
        using (var client = _server.CreateClient(sftpSecret, AddUser(UserProtocols.All, sftp)))
        {
            client.Connect();
            Assert.True(client.IsConnected);
        }

        var (webdav, webdavSecret) = AppPasswordGenerator.Create("finder", UserProtocols.WebDav, DateTime.UtcNow, null);
        using var refused = _server.CreateClient(webdavSecret, AddUser(UserProtocols.All, webdav));
        Assert.Throws<SshAuthenticationException>(() => refused.Connect());
    }
}
