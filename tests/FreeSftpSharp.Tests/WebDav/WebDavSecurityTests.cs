using System.Net;
using System.Text;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.Users;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.WebDav;

/// <summary>The login, the sessions, the protocol flag, the permissions, the events and the storage capabilities of WebDAV.</summary>
public sealed class WebDavSecurityTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task NoCredentials_GetsABasicChallenge()
    {
        await using var host = await WebDavTestHost.StartAsync();
        var response = await host.Client(null).SendAsync("PROPFIND", "/dav/", null, ("Depth", "0"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.Equal("Basic", challenge.Scheme);
        Assert.Contains("realm=\"FreeSftpSharp\"", challenge.Parameter);
    }

    [Fact]
    public async Task WrongPasswordOrUnknownUser_Is401_WithAWebDavLoginFailedEvent()
    {
        await using var host = await WebDavTestHost.StartAsync();
        host.AddUser("alice");

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.Client("alice", "wrong-password").SendAsync("OPTIONS", "/dav/")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.Client("nobody").SendAsync("OPTIONS", "/dav/")).StatusCode);

        var failures = host.Events.Published.OfType<AuthEvent>().Where(e => e.Type == AuthEventType.LoginFailed).ToList();
        Assert.Equal(2, failures.Count);
        Assert.All(failures, e => Assert.Equal(ConnectionProtocols.WebDav, e.Protocol));
        Assert.Empty(host.Connections.GetAll());
    }

    [Fact]
    public async Task PlainHttp_FromAnotherHost_IsRefused_FromLoopbackOrWithTheSetting_IsAllowed()
    {
        await using var host = await WebDavTestHost.StartAsync();
        host.AddUser("alice");
        var http = host.Client("alice", baseAddress: "http://localhost/");

        var remote = await http.SendAsync("OPTIONS", "/dav/", null, (WebDavTestHost.RemoteIpHeader, "192.0.2.10"));
        Assert.Equal(HttpStatusCode.Forbidden, remote.StatusCode);
        Assert.Contains("HTTPS", await remote.Content.ReadAsStringAsync(Ct));
        Assert.DoesNotContain(host.Events.Published.OfType<AuthEvent>(), e => e.Type == AuthEventType.LoginFailed);

        Assert.Equal(HttpStatusCode.OK, (await http.SendAsync("OPTIONS", "/dav/")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await host.Client("alice").SendAsync("OPTIONS", "/dav/", null, (WebDavTestHost.RemoteIpHeader, "192.0.2.10"))).StatusCode);

        await using var insecure = await WebDavTestHost.StartAsync(settings: new Dictionary<string, string?> { ["WebDav:AllowInsecureHttp"] = "true" });
        insecure.AddUser("alice");
        Assert.Equal(HttpStatusCode.OK, (await insecure.Client("alice", baseAddress: "http://localhost/")
            .SendAsync("OPTIONS", "/dav/", null, (WebDavTestHost.RemoteIpHeader, "192.0.2.10"))).StatusCode);
    }

    [Fact]
    public async Task UserWithoutTheWebDavProtocol_Gets403()
    {
        await using var host = await WebDavTestHost.StartAsync();
        host.AddUser("sftp-only", u => u.AllowedProtocols = UserProtocols.Sftp);

        var response = await host.Client("sftp-only").SendAsync("PROPFIND", "/dav/", null, ("Depth", "0"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains(host.Events.Published.OfType<AuthEvent>(),
            e => e is { Type: AuthEventType.LoginFailed, Reason: "the protocol is not allowed for the user" });
        // With a wrong password the client learns nothing about the protocol.
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.Client("sftp-only", "wrong").SendAsync("OPTIONS", "/dav/")).StatusCode);
    }

    [Fact]
    public async Task MultiStepUser_NeedsAnAppPasswordForWebDav()
    {
        await using var host = await WebDavTestHost.StartAsync();
        var user = host.AddUser("bob", u => u.RequireAllOf = [AuthMethods.PublicKey, AuthMethods.Password]);
        var (webdav, webdavSecret) = AppPasswordGenerator.Create("Finder", UserProtocols.WebDav, DateTime.UtcNow, null);
        var (sftpOnly, sftpSecret) = AppPasswordGenerator.Create("sftp", UserProtocols.Sftp, DateTime.UtcNow, null);
        var (expired, expiredSecret) = AppPasswordGenerator.Create("old", UserProtocols.WebDav, DateTime.UtcNow.AddDays(-2), DateTime.UtcNow.AddDays(-1));
        user.AppPasswords = [webdav, sftpOnly, expired];
        host.Repository.UpdateUser(user);

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.Client("bob").SendAsync("OPTIONS", "/dav/")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.Client("bob", sftpSecret).SendAsync("OPTIONS", "/dav/")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.Client("bob", expiredSecret).SendAsync("OPTIONS", "/dav/")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await host.Client("bob", webdavSecret).SendAsync("OPTIONS", "/dav/")).StatusCode);

        var login = host.Events.Published.OfType<AuthEvent>().Single(e => e.Type == AuthEventType.LoginOk);
        Assert.Equal("app-password", login.Method);
        Assert.DoesNotContain(webdavSecret, string.Join("|", host.Repository.GetUser("bob").AppPasswords!.Select(a => a.SecretHash)));
    }

    [Fact]
    public async Task TotpUser_NeedsAnAppPasswordForWebDav()
    {
        await using var host = await WebDavTestHost.StartAsync();
        var user = host.AddUser("tina", u => u.Id = 42);
        var (entry, secret) = AppPasswordGenerator.Create("Explorer", UserProtocols.WebDav, DateTime.UtcNow, null);
        user.AppPasswords = [entry];
        host.Repository.UpdateUser(user);
        host.TwoFactor.UserIds.Add(42);

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.Client("tina").SendAsync("OPTIONS", "/dav/")).StatusCode);
        Assert.Contains(host.Events.Published.OfType<AuthEvent>(),
            e => e is { Type: AuthEventType.LoginFailed, Reason: "the user has a second factor; use an app password" });
        Assert.Equal(HttpStatusCode.OK, (await host.Client("tina", secret).SendAsync("OPTIONS", "/dav/")).StatusCode);
    }

    [Fact]
    public async Task LifecycleRules_DisabledOrExpiredUser_AndTheSessionLimit()
    {
        await using var host = await WebDavTestHost.StartAsync();
        host.AddUser("off", u => u.Status = UserStatus.Disabled);
        host.AddUser("old", u => u.ExpiresAt = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        host.AddUser("one", u => u.MaxSessions = 1);

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.Client("off").SendAsync("OPTIONS", "/dav/")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.Client("old").SendAsync("OPTIONS", "/dav/")).StatusCode);
        Assert.Contains(host.Events.Published.OfType<AuthEvent>(), e => e is { Type: AuthEventType.LoginFailed, Reason: "the user is disabled" });

        Assert.Equal(HttpStatusCode.OK, (await host.Client("one").SendAsync("OPTIONS", "/dav/")).StatusCode);
        // Another address is another session: the limit of one refuses it.
        var second = await host.Client("one").SendAsync("OPTIONS", "/dav/", null, (WebDavTestHost.RemoteIpHeader, "::1"));
        Assert.Equal(HttpStatusCode.Forbidden, second.StatusCode);
        Assert.Single(host.Connections.GetAll());
        Assert.Contains(host.Events.Published.OfType<AuthEvent>(), e => e is { Type: AuthEventType.LoginFailed, Username: "one" }
            && e.Reason!.Contains("maximum of 1 session"));
    }

    [Fact]
    public async Task FailedLogins_BanTheAddress()
    {
        await using var host = await WebDavTestHost.StartAsync();
        host.AddUser("alice");
        const string attacker = "192.0.2.66";
        for (var i = 0; i < 5; i++)
            Assert.Equal(HttpStatusCode.Unauthorized,
                (await host.Client("alice", "guess" + i).SendAsync("OPTIONS", "/dav/", null, (WebDavTestHost.RemoteIpHeader, attacker))).StatusCode);

        var banned = await host.Client("alice").SendAsync("OPTIONS", "/dav/", null, (WebDavTestHost.RemoteIpHeader, attacker));
        Assert.Equal(HttpStatusCode.Forbidden, banned.StatusCode);
        Assert.Contains(host.Events.Published.OfType<AuthEvent>(), e => e is { Type: AuthEventType.IpBanned, Protocol: ConnectionProtocols.WebDav });
        Assert.Equal(HttpStatusCode.OK, (await host.Client("alice").SendAsync("OPTIONS", "/dav/")).StatusCode);
    }

    [Fact]
    public async Task Session_OneLoginAndOneRegistryConnectionForManyRequests_EndsWhenIdle()
    {
        await using var host = await WebDavTestHost.StartAsync();
        host.AddUser("alice");
        var client = host.Client("alice");
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft-WebDAV-MiniRedir/10.0.19045");

        for (var i = 0; i < 3; i++)
            Assert.Equal(HttpStatusCode.MultiStatus, (await client.SendAsync("PROPFIND", "/dav/", null, ("Depth", "1"))).StatusCode);

        var connection = Assert.Single(host.Connections.GetAll());
        Assert.Equal(ConnectionProtocols.WebDav, connection.Protocol);
        Assert.Equal("alice", connection.Username);
        Assert.Equal("password", connection.AuthMethod);
        Assert.Equal("Microsoft-WebDAV-MiniRedir/10.0.19045", connection.ClientVersion);
        var login = Assert.Single(host.Events.Published.OfType<AuthEvent>(), e => e.Type == AuthEventType.LoginOk);
        Assert.Equal(connection.Id.ToString(), login.SessionId);
        Assert.NotNull(host.Repository.GetUser("alice").LastLoginAt);

        // The sweeper of the host runs on the fake clock too; the direct call covers a sweep that has not run yet.
        host.Time.Advance(TimeSpan.FromSeconds(301));
        await host.Sessions.RemoveIdleAsync();
        for (var i = 0; i < 100 && host.Connections.GetAll().Count > 0; i++)
            await Task.Delay(20, Ct);
        Assert.Empty(host.Connections.GetAll());
        Assert.Single(host.Events.Published.OfType<AuthEvent>(), e => e.Type == AuthEventType.Logout && e.SessionId == login.SessionId);
    }

    [Fact]
    public async Task Session_EndsWhenTheUserChanges_AndWhenAnAdministratorDisconnectsIt()
    {
        await using var host = await WebDavTestHost.StartAsync();
        var user = host.AddUser("alice");
        var client = host.Client("alice");
        await client.SendAsync("OPTIONS", "/dav/");
        var first = Assert.Single(host.Connections.GetAll());

        user = host.Repository.GetUser("alice");
        user.AllowedProtocols = UserProtocols.Sftp;
        host.Repository.UpdateUser(user);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync("OPTIONS", "/dav/")).StatusCode);
        Assert.Empty(host.Connections.GetAll());

        user.AllowedProtocols = UserProtocols.All;
        host.Repository.UpdateUser(user);
        await client.SendAsync("OPTIONS", "/dav/");
        var second = Assert.Single(host.Connections.GetAll());
        Assert.NotEqual(first.Id, second.Id);

        Assert.True(await host.Connections.DisconnectAsync(second.Id, "test"));
        Assert.Equal(0, host.Sessions.Count);
        await client.SendAsync("OPTIONS", "/dav/");
        Assert.Equal(3, host.Events.Published.OfType<AuthEvent>().Count(e => e.Type == AuthEventType.LoginOk));
    }

    [Fact]
    public async Task FileOperations_PublishWebDavEventsThroughTheDecoratorChain()
    {
        await using var host = await WebDavTestHost.StartAsync();
        host.AddUser("alice");
        var client = host.Client("alice");

        await client.PutAsync("/dav/report.txt", "hello");
        await client.GetAsync("/dav/report.txt", Ct);
        await client.SendAsync("MKCOL", "/dav/dir/");
        await client.SendAsync("MOVE", "/dav/report.txt", null, ("Destination", "/dav/dir/report.txt"));
        await client.DeleteAsync("/dav/dir/report.txt", Ct);

        var events = host.Events.FileEvents;
        var session = Assert.Single(host.Connections.GetAll()).Id.ToString();
        Assert.All(events, e =>
        {
            Assert.Equal(ConnectionProtocols.WebDav, e.Protocol);
            Assert.Equal("alice", e.Username);
            Assert.Equal(session, e.SessionId);
            Assert.Equal("127.0.0.1", e.RemoteIp);
        });
        var types = events.Where(e => !e.IsPreEvent).Select(e => e.Type).ToList();
        Assert.Contains(FileEventType.FirstUpload, types);
        Assert.Contains(FileEventType.Download, types);
        Assert.Contains(FileEventType.Mkdir, types);
        Assert.Contains(events, e => e.Type == FileEventType.Rename && e.VirtualPath == "/report.txt" && e.VirtualTargetPath == "/dir/report.txt");
        Assert.Contains(FileEventType.Delete, types);
        Assert.Equal(5, events.Single(e => e.Type == FileEventType.FirstUpload).FileSize);
    }

    [Fact]
    public async Task HookDeny_Is403_WithTheMessageOfTheHook()
    {
        await using var host = await WebDavTestHost.StartAsync();
        host.AddUser("alice");
        host.Events.Decide = e => e is FileEvent { Type: FileEventType.PreUpload } ? HookDecision.Deny("test hook", "No uploads today.") : HookDecision.Allow;

        var response = await host.Client("alice").PutAsync("/dav/x", "y");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("No uploads today.", await response.Content.ReadAsStringAsync(Ct));
        Assert.Null(await host.StorageOf("alice").StatAsync("/x", true, CancellationToken.None));
    }

    [Fact]
    public async Task Permissions_DenialsAre403()
    {
        await using var host = await WebDavTestHost.StartAsync();
        host.AddUser("reader", u => u.Permissions = new() { ["/"] = FilePermissions.List | FilePermissions.Download });
        var storage = host.StorageOf("reader");
        await using (var handle = await storage.OpenAsync("/existing", FileOpenFlags.Write | FileOpenFlags.Create, null, CancellationToken.None))
            await handle.WriteAsync(0, Encoding.UTF8.GetBytes("data"), CancellationToken.None);
        var client = host.Client("reader");

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/dav/existing", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.MultiStatus, (await client.SendAsync("PROPFIND", "/dav/", null, ("Depth", "1"))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PutAsync("/dav/new", "x")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PutAsync("/dav/existing", "x")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.DeleteAsync("/dav/existing", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync("MKCOL", "/dav/dir/")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync("MOVE", "/dav/existing", null, ("Destination", "/dav/moved"))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync("COPY", "/dav/existing", null, ("Destination", "/dav/copy"))).StatusCode);
        Assert.Equal("data", Encoding.UTF8.GetString(await (await client.GetAsync("/dav/existing", Ct)).Content.ReadAsByteArrayAsync(Ct)));
        Assert.Contains(host.Events.FileEvents, e => e is { Type: FileEventType.Upload or FileEventType.FirstUpload, Status: FileEventStatus.Error });
    }

    [Fact]
    public async Task CloudLikeStorage_WithoutRandomWritesOrTimes_StillWorks()
    {
        // An object store: sequential writes only, no times, no rename.
        await using var host = await WebDavTestHost.StartAsync(StorageCapabilities.None);
        host.AddUser("alice");
        var client = host.Client("alice");
        var big = new string('x', 300_000); // several write calls

        Assert.Equal(HttpStatusCode.Created, (await client.PutAsync("/dav/big.bin", big)).StatusCode);
        Assert.Equal(big, await (await client.GetAsync("/dav/big.bin", Ct)).Content.ReadAsStringAsync(Ct));
        Assert.Equal(HttpStatusCode.NoContent, (await client.PutAsync("/dav/big.bin", "small")).StatusCode);
        Assert.Equal("small", await (await client.GetAsync("/dav/big.bin", Ct)).Content.ReadAsStringAsync(Ct));
        Assert.Equal(HttpStatusCode.Created, (await client.SendAsync("COPY", "/dav/big.bin", null, ("Destination", "/dav/copy.bin"))).StatusCode);

        const string proppatch = """
            <?xml version="1.0" encoding="utf-8"?>
            <D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><D:getlastmodified>Mon, 12 Jan 1998 09:25:56 GMT</D:getlastmodified></D:prop></D:set></D:propertyupdate>
            """;
        var patched = await client.SendAsync("PROPPATCH", "/dav/big.bin", proppatch);
        Assert.Equal(HttpStatusCode.MultiStatus, patched.StatusCode);
        Assert.Contains("403", await patched.Content.ReadAsStringAsync(Ct));

        // MOVE needs the rename of the storage: 502 as RFC 4918 says for a destination that cannot take it.
        Assert.Equal(HttpStatusCode.BadGateway, (await client.SendAsync("MOVE", "/dav/big.bin", null, ("Destination", "/dav/moved.bin"))).StatusCode);
        Assert.NotNull(await host.StorageOf("alice").StatAsync("/big.bin", true, CancellationToken.None));
    }

    [Fact]
    public async Task Disabled_MapsNothing()
    {
        await using var host = await WebDavTestHost.StartAsync(settings: new Dictionary<string, string?> { ["WebDav:Enabled"] = "false" });
        host.AddUser("alice");
        Assert.Equal((HttpStatusCode)418, (await host.Client("alice").SendAsync("PROPFIND", "/dav/", null, ("Depth", "0"))).StatusCode);
    }

    [Fact]
    public async Task OtherPath_IsNotWebDav_AndACustomPathWorks()
    {
        await using var host = await WebDavTestHost.StartAsync(settings: new Dictionary<string, string?> { ["WebDav:Path"] = "/files/" });
        host.AddUser("alice");
        var client = host.Client("alice");
        Assert.Equal((HttpStatusCode)418, (await client.SendAsync("PROPFIND", "/dav/", null, ("Depth", "0"))).StatusCode);
        Assert.Equal((HttpStatusCode)418, (await client.GetAsync("/filesystem", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await client.PutAsync("/files/a.txt", "x")).StatusCode);
        var listing = await client.SendAsync("PROPFIND", "/files", null, ("Depth", "1"));
        Assert.Contains("<D:href>/files/a.txt</D:href>", await listing.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task RootPathWithoutAPort_IsRefusedAtTheStart()
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(() =>
            WebDavTestHost.StartAsync(settings: new Dictionary<string, string?> { ["WebDav:Path"] = "/" }));
        Assert.Contains("WebDav:Port", error.ToString());
    }
}
