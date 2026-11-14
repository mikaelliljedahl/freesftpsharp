using System.Diagnostics;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Webhooks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SshServer.Authentication.Http;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Permissions;
using SshServer.Webhooks;
using SshServerModule.Authentication;

namespace FreeSftpSharp.Tests.Authentication;

/// <summary>Builds the <see cref="IUserAuthenticator"/> of the hosts with the HTTP hook (AddSshServerAuthentication + AddHttpAuthHook).</summary>
internal static class HttpAuthHookSetup
{
    public const string Secret = "hook-secret-of-the-tests";

    public static ServiceProvider Build(ISettingsRepository repository, string url, int timeoutSeconds = 10, ILoggerProvider? logs = null,
        string? externalUsersRoot = null)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Auth:HttpHook:Url"] = url,
            ["Auth:HttpHook:Secret"] = Secret,
            ["Auth:HttpHook:TimeoutSeconds"] = timeoutSeconds.ToString(),
            ["Auth:ExternalUsers:RootDirectory"] = externalUsersRoot,
        }).Build();
        var services = new ServiceCollection().AddLogging(b =>
        {
            b.SetMinimumLevel(LogLevel.Trace);
            if (logs != null)
                b.AddProvider(logs);
        });
        services.AddSingleton(repository);
        services.AddSshServerAuthentication(configuration);
        services.AddHttpAuthHook(configuration);
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true });
    }
}

/// <summary>A logger provider that keeps every message, to check that no password is logged.</summary>
internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    public System.Collections.Concurrent.ConcurrentQueue<string> Messages { get; } = new();

    public ILogger CreateLogger(string categoryName) => new Logger(this);

    public void Dispose()
    {
    }

    private sealed class Logger(CapturingLoggerProvider owner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            owner.Messages.Enqueue(formatter(state, exception) + " " + exception);
    }
}

/// <summary>The external HTTP authentication hook (issue #64) against an in-process Kestrel receiver.</summary>
public sealed class HttpAuthHookTests : IAsyncLifetime
{
    private const string Password = "the-password-of-alice";
    private readonly InMemorySettingsRepository _repository = new(new ServerSettings());
    private readonly CapturingLoggerProvider _logs = new();
    private WebhookReceiver _receiver = null!;
    private ServiceProvider _services = null!;
    private IUserAuthenticator _authenticator = null!;

    public async ValueTask InitializeAsync()
    {
        _receiver = await WebhookReceiver.StartAsync();
        _services = HttpAuthHookSetup.Build(_repository, _receiver.Url("/auth"), timeoutSeconds: 1, _logs);
        _authenticator = _services.GetRequiredService<IUserAuthenticator>();
    }

    public async ValueTask DisposeAsync()
    {
        await _services.DisposeAsync();
        await _receiver.DisposeAsync();
    }

    private static AuthRequest Request(string username = "alice", string? password = Password, byte[]? key = null) => new()
    {
        Username = username, Method = key != null ? AuthMethods.PublicKey : AuthMethods.Password, Password = key != null ? null : password,
        PublicKey = key, Protocol = "SSH", RemoteIp = "192.0.2.7",
    };

    [Fact]
    public async Task A_200_with_a_user_accepts_and_gives_the_user()
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(200,
            """{"username":"alice","primary_group":"staff","groups":["a","b"],"permissions":{"/":["List","Download"],"/in":["upload"]},"allowed_ips":["10.0.0.0/8"],"max_sessions":2,"description":"from the hook"}""");

        var check = await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.True(check.Succeeded);
        Assert.Equal("http", check.Provider);
        Assert.True(check.NeedsSave);
        var user = check.User!;
        Assert.Equal(FilePermissions.List | FilePermissions.Download, user.Permissions!["/"]);
        Assert.Equal(FilePermissions.Upload, user.Permissions["/in"]);
        Assert.Equal(["10.0.0.0/8"], user.WhitelistedIps);
        Assert.True(user.OnlyWhitelistedIps);
        Assert.Equal(2, user.MaxSessions);
        Assert.Equal("from the hook", user.Description);
    }

    [Fact]
    public async Task A_200_with_a_user_in_the_rest_api_format_accepts_without_a_warning()
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(200,
            """{"username":"alice","primaryGroup":"staff","groups":["a"],"permissions":{"/":["List","Download"],"/in":["upload"]},"whitelistedIps":["10.0.0.0/8"],"maxSessions":3,"description":"camel"}""");

        var check = await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.True(check.Succeeded);
        var user = check.User!;
        Assert.Equal(FilePermissions.List | FilePermissions.Download, user.Permissions!["/"]);
        Assert.Equal(FilePermissions.Upload, user.Permissions["/in"]);
        Assert.Equal(["10.0.0.0/8"], user.WhitelistedIps);
        Assert.True(user.OnlyWhitelistedIps);
        Assert.Equal(3, user.MaxSessions);
        Assert.Equal("camel", user.Description);
        Assert.DoesNotContain(_logs.Messages, m => m.Contains("deprecated", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_new_format_can_keep_a_network_list_without_enforcing_it()
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(200, """{"onlyWhitelistedIps":false,"whitelistedIps":["10.0.0.0/8"]}""");

        var check = await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.True(check.Succeeded);
        Assert.Equal(["10.0.0.0/8"], check.User!.WhitelistedIps);
        Assert.False(check.User.OnlyWhitelistedIps);
    }

    [Fact]
    public async Task The_allowed_protocols_have_the_rest_api_format()
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(200, """{"allowedProtocols":["SFTP","webdav"]}""");

        var check = await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.True(check.Succeeded);
        Assert.Equal(UserProtocols.Sftp | UserProtocols.WebDav, check.User!.AllowedProtocols);
    }

    [Fact]
    public async Task All_allows_every_protocol()
    {
        _repository.AddUser(new User { Username = "alice", AuthenticationProvider = "http", AllowedProtocols = UserProtocols.Ftp });
        _receiver.Respond = (_, _) => new ReceiverAnswer(200, """{"allowedProtocols":["all"]}""");

        var check = await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.True(check.Succeeded);
        Assert.True(check.NeedsSave);
        Assert.Equal(UserProtocols.All, check.User!.AllowedProtocols);
    }

    [Fact]
    public async Task No_allowed_protocol_refuses()
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(200, """{"allowedProtocols":[]}""");

        var check = await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.Contains("allow at least one protocol", check.Reason);
    }

    [Fact]
    public async Task The_deprecated_snake_case_answer_is_still_accepted_with_one_warning_per_process()
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(200, """{"primary_group":"staff","allowed_ips":["10.0.0.0/8"],"max_sessions":2}""");

        var first = await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);
        var second = await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.True(first.Succeeded);
        Assert.True(second.Succeeded);
        Assert.Equal(2, second.User!.MaxSessions);
        Assert.Equal(["10.0.0.0/8"], second.User.WhitelistedIps);
        Assert.True(second.User.OnlyWhitelistedIps);
        Assert.Single(_logs.Messages, m => m.Contains("deprecated snake_case format", StringComparison.Ordinal));
    }

    [Fact]
    public async Task An_answer_that_mixes_both_formats_for_one_field_refuses()
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(200, """{"max_sessions":2,"maxSessions":3}""");

        var check = await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.Equal("the answer is not a valid user: the answer has both \"max_sessions\" and \"maxSessions\"", check.Reason);
    }

    [Fact]
    public async Task The_request_has_the_credential_and_a_valid_signature()
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(200, "{}");

        await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        var request = Assert.Single(_receiver.Requests);
        Assert.Equal("POST", request.Method);
        Assert.Equal("alice", request.Json.GetProperty("username").GetString());
        Assert.Equal(Password, request.Json.GetProperty("password").GetString());
        Assert.Equal("password", request.Json.GetProperty("method").GetString());
        Assert.Equal("192.0.2.7", request.Json.GetProperty("ip").GetString());
        Assert.Equal("SSH", request.Json.GetProperty("protocol").GetString());
        Assert.True(WebhookSignature.Verify(HttpAuthHookSetup.Secret, request.Header(WebhookSignature.SignatureHeader), request.Body,
            DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public async Task A_public_key_is_sent_as_an_authorized_keys_line_without_a_password()
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(200, "{}");
        var key = TestUserKeys.Ed25519();
        var blob = key.Entry.KeyBase64;

        await _authenticator.VerifyAsync(Request(key: key.Blob), TestContext.Current.CancellationToken);

        var json = Assert.Single(_receiver.Requests).Json;
        Assert.Equal("ssh-ed25519 " + blob, json.GetProperty("public_key").GetString());
        Assert.False(json.TryGetProperty("password", out _));
    }

    [Theory]
    [InlineData(403)]
    [InlineData(401)]
    [InlineData(500)]
    [InlineData(302)]
    public async Task Any_other_status_refuses(int status)
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(status, "{}", Location: status == 302 ? _receiver.Url("/elsewhere") : null);

        var check = await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.Equal($"the authentication hook answered HTTP {status}", check.Reason);
        Assert.Single(_receiver.Requests); // a redirect is not followed
    }

    [Fact]
    public async Task A_204_is_not_handled_and_the_user_stays_unknown()
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(204);

        var check = await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.Equal("unknown user", check.Reason);
    }

    [Fact]
    public async Task A_timeout_refuses_within_the_limit()
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(200, "{}", Delay: TimeSpan.FromSeconds(10));

        var watch = Stopwatch.StartNew();
        var check = await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.Equal("the authentication hook did not answer within 1 s", check.Reason);
        Assert.InRange(watch.Elapsed.TotalSeconds, 0.5, 5);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[1,2]")]
    [InlineData("""{"username":"mallory"}""")]
    [InlineData("""{"permissions":{"/":["Everything"]}}""")]
    [InlineData("""{"max_sessions":"many"}""")]
    [InlineData("""{"maxSessions":"many"}""")]
    [InlineData("""{"whitelistedIps":"10.0.0.0/8"}""")]
    [InlineData("""{"permissions":{"/":null}}""")]
    [InlineData("""{"allowedProtocols":["gopher"]}""")]
    public async Task An_answer_that_is_not_a_valid_user_refuses(string body)
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(200, body);

        var check = await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.StartsWith("the answer is not a valid user", check.Reason);
    }

    [Fact]
    public async Task An_answer_over_64_KiB_refuses()
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(200, "{\"description\":\"" + new string('x', 70 * 1024) + "\"}");

        var check = await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.Equal("the answer is larger than 64 KiB", check.Reason);
    }

    [Fact]
    public async Task An_unreachable_hook_refuses()
    {
        var url = _receiver.Url("/auth");
        await _receiver.DisposeAsync();
        _receiver = await WebhookReceiver.StartAsync(); // another port; the old one is closed

        var services = HttpAuthHookSetup.Build(_repository, url, logs: _logs);
        await using var _ = services;
        var check = await services.GetRequiredService<IUserAuthenticator>().VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.StartsWith("the authentication hook cannot be reached", check.Reason);
    }

    [Fact]
    public async Task The_password_is_never_logged()
    {
        _receiver.Respond = (_, index) => index switch
        {
            0 => new ReceiverAnswer(403),
            1 => new ReceiverAnswer(200, "not json"),
            _ => new ReceiverAnswer(200, "{}", Delay: TimeSpan.FromSeconds(5)),
        };

        for (var i = 0; i < 3; i++)
            await _authenticator.VerifyAsync(Request(), TestContext.Current.CancellationToken);

        Assert.NotEmpty(_logs.Messages);
        Assert.DoesNotContain(_logs.Messages, m => m.Contains(Password, StringComparison.Ordinal));
    }

    [Fact]
    public void Without_a_url_nothing_is_registered()
    {
        var services = new ServiceCollection();
        services.AddHttpAuthHook(new ConfigurationBuilder().Build());
        Assert.Empty(services);
    }

    [Theory]
    [InlineData("https://auth.example.com/sftp", true)]
    [InlineData("http://localhost:5000/auth", true)]
    [InlineData("http://127.0.0.1:5000/auth", true)]
    [InlineData("http://[::1]:5000/auth", true)]
    [InlineData("http://auth.example.com/sftp", false)]
    [InlineData("http://10.0.0.5/auth", false)]
    [InlineData("https://user:secret@auth.example.com/", false)]
    [InlineData("ftp://auth.example.com/", false)]
    public void The_password_goes_only_over_https_or_to_localhost(string url, bool valid)
    {
        Assert.Equal(valid, HttpAuthHookOptionsValidator.ValidateUrl(url) == null);
    }

    [Fact]
    public void The_options_check_the_secret_and_the_timeout()
    {
        var result = new HttpAuthHookOptionsValidator().Validate(null, new HttpAuthHookOptions
        {
            Url = "https://auth.example.com/", Secret = "short", TimeoutSeconds = 0,
        });

        Assert.True(result.Failed);
        Assert.Equal(2, result.Failures!.Count());
    }
}
