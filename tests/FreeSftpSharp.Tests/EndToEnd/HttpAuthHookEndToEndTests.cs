using System.Collections.Concurrent;
using System.Diagnostics;
using FreeSftpSharp.Tests.Authentication;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Webhooks;
using Microsoft.Extensions.DependencyInjection;
using Renci.SshNet;
using Renci.SshNet.Common;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Groups;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>The SFTP server with the HTTP authentication hook (#64) on an in-process Kestrel receiver.</summary>
public sealed class HttpAuthHookServerFixture : SftpServerFixture
{
    public const int HookTimeoutSeconds = 2;
    private ServiceProvider? _services;

    public WebhookReceiver Hook { get; private set; } = null!;

    /// <summary>The answer of the hook per user name; a name without an answer gets 403.</summary>
    public ConcurrentDictionary<string, ReceiverAnswer> Answers { get; } = new(StringComparer.Ordinal);

    public string ExternalRoot => Path.Combine(TempDirectory, "external");

    public override async ValueTask InitializeAsync()
    {
        Hook = await WebhookReceiver.StartAsync();
        Hook.Respond = (request, _) => Answers.TryGetValue(request.Json.GetProperty("username").GetString()!, out var answer) ? answer : new ReceiverAnswer(403);
        await base.InitializeAsync();
    }

    protected override IUserAuthenticator CreateAuthenticator(ISettingsRepository repository)
    {
        _services?.Dispose();
        _services = HttpAuthHookSetup.Build(repository, Hook.Url("/auth"), HookTimeoutSeconds, externalUsersRoot: ExternalRoot);
        return _services.GetRequiredService<IUserAuthenticator>();
    }

    public int RequestsFor(string username) => Hook.Requests.Count(r => r.Json.GetProperty("username").GetString() == username);

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        if (_services != null)
            await _services.DisposeAsync();
        await Hook.DisposeAsync();
    }
}

/// <summary>
/// Issue #64 with SSH.NET: a user that does not exist locally logs in through the HTTP hook, is created with the
/// returned permissions and group, and is refused with a 403, a timeout, or a local disable.
/// </summary>
public sealed class HttpAuthHookEndToEndTests : IClassFixture<HttpAuthHookServerFixture>
{
    private readonly HttpAuthHookServerFixture _server;

    public HttpAuthHookEndToEndTests(HttpAuthHookServerFixture server)
    {
        _server = server;
    }

    private static string NewName() => "hook-" + Guid.NewGuid().ToString("N")[..8];

    [Fact]
    public void A_user_of_the_hook_logs_in_and_is_created_with_the_returned_permissions_and_group()
    {
        var group = new Group { Name = "staff-" + Guid.NewGuid().ToString("N")[..6] };
        _server.Repository.AddGroup(group);
        var username = NewName();
        _server.Answers[username] = new ReceiverAnswer(200,
            $$"""{"username":"{{username}}","primary_group":"{{group.Name}}","permissions":{"/":["List","Download"]},"description":"from the hook"}""");
        Assert.Null(_server.Repository.GetUser(username));

        using (var client = _server.CreateClient("the-directory-password", username))
        {
            client.Connect();
            Assert.DoesNotContain(client.ListDirectory("/"), f => f.Name is not ("." or ".."));
            // The returned permissions apply: no upload.
            Assert.Throws<SftpPermissionDeniedException>(() => client.UploadFile(new MemoryStream([1, 2, 3]), "/new.txt"));
        }

        var stored = _server.Repository.GetUser(username);
        Assert.NotNull(stored);
        Assert.Equal("http", stored.AuthenticationProvider);
        Assert.Equal(group.Id, stored.PrimaryGroupId);
        Assert.Null(stored.HashedPassword);
        Assert.Equal("from the hook", stored.Description);
        Assert.Equal(Path.Combine(_server.ExternalRoot, username), stored.UserRootDirectory);
        Assert.NotNull(stored.LastLoginAt);

        // The next login asks the hook again: the password is never stored here.
        _server.Answers[username] = new ReceiverAnswer(403);
        using var refused = _server.CreateClient("the-directory-password", username);
        Assert.Throws<SshAuthenticationException>(() => refused.Connect());
    }

    [Fact]
    public void A_403_refuses_and_creates_no_user()
    {
        var username = NewName();
        _server.Answers[username] = new ReceiverAnswer(403);

        using var client = _server.CreateClient("whatever", username);
        Assert.Throws<SshAuthenticationException>(() => client.Connect());

        Assert.True(_server.RequestsFor(username) >= 1);
        Assert.Null(_server.Repository.GetUser(username));
    }

    [Fact]
    public void A_timeout_of_the_hook_refuses_within_the_limit()
    {
        var username = NewName();
        _server.Answers[username] = new ReceiverAnswer(200, "{}", Delay: TimeSpan.FromSeconds(30));

        var watch = Stopwatch.StartNew();
        using var client = _server.CreateClient("whatever", username);
        client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(30);
        Assert.Throws<SshAuthenticationException>(() => client.Connect());

        // SSH.NET tries the password once (and keyboard-interactive is not offered without a handler).
        Assert.InRange(watch.Elapsed.TotalSeconds, HttpAuthHookServerFixture.HookTimeoutSeconds - 0.5, 20);
        Assert.Null(_server.Repository.GetUser(username));
    }

    [Fact]
    public void A_user_disabled_locally_is_refused_although_the_hook_accepts_it()
    {
        var username = NewName();
        _server.Answers[username] = new ReceiverAnswer(200, "{}");
        using (var client = _server.CreateClient("pw", username))
            client.Connect();
        var user = _server.Repository.GetUser(username);
        user.Status = UserStatus.Disabled;
        _server.Repository.UpdateUser(user);
        var before = _server.RequestsFor(username);

        using var refused = _server.CreateClient("pw", username);
        Assert.Throws<SshAuthenticationException>(() => refused.Connect());

        Assert.Equal(before, _server.RequestsFor(username)); // refused before the hook is asked
    }

    [Fact]
    public void A_local_user_is_not_checked_by_the_hook()
    {
        _server.Answers[_server.Username] = new ReceiverAnswer(200, "{}");

        using (var client = _server.CreateClient("not-the-local-password"))
            Assert.Throws<SshAuthenticationException>(() => client.Connect());
        using (var client = _server.CreateClient())
            client.Connect();

        Assert.Equal(0, _server.RequestsFor(_server.Username));
    }

    [Fact]
    public void A_public_key_accepted_by_the_hook_logs_in_after_the_signature_check()
    {
        var username = NewName();
        var key = TestUserKeys.Ed25519();
        _server.Answers[username] = new ReceiverAnswer(200, "{}");

        using (var client = new SftpClient(new ConnectionInfo(SftpServerFixture.Host, _server.Port, username,
                   new PrivateKeyAuthenticationMethod(username, key.ToPrivateKeyFile())) { Timeout = TimeSpan.FromSeconds(15) }))
        {
            client.Connect();
            Assert.True(client.IsConnected);
        }

        var request = _server.Hook.Requests.First(r => r.Json.GetProperty("username").GetString() == username);
        Assert.Equal(key.Entry.KeyType + " " + key.Entry.KeyBase64, request.Json.GetProperty("public_key").GetString());
        Assert.Equal("http", _server.Repository.GetUser(username).AuthenticationProvider);
    }
}
