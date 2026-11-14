using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Permissions;
using SshServerModule.Authentication;

namespace FreeSftpSharp.Tests.Authentication;

/// <summary>A provider for the chain tests: answers with a function and keeps the requests.</summary>
internal sealed class FakeAuthenticationProvider : IAuthenticationProvider
{
    private readonly Func<AuthRequest, AuthResult> _answer;

    public FakeAuthenticationProvider(string name, Func<AuthRequest, AuthResult> answer)
    {
        Name = name;
        _answer = answer;
    }

    public string Name { get; }

    public List<AuthRequest> Calls { get; } = new();

    public ValueTask<AuthResult> AuthenticateAsync(AuthRequest request, CancellationToken ct)
    {
        Calls.Add(request);
        return ValueTask.FromResult(_answer(request));
    }
}

/// <summary>The chain of the authentication providers (issue #64): order, ownership, fail closed, just-in-time users.</summary>
public sealed class UserAuthenticatorTests
{
    private readonly InMemorySettingsRepository _repository = new(new ServerSettings());

    public UserAuthenticatorTests()
    {
        _repository.AddUser(new User { Username = "local", HashedPassword = TestCredentials.HashPassword("local-password") });
    }

    private UserAuthenticator Create(IEnumerable<IAuthenticationProvider> external, params string[] order)
    {
        var providers = new List<IAuthenticationProvider> { new DatabaseAuthenticationProvider(_repository) };
        providers.AddRange(external);
        return new UserAuthenticator(providers, _repository, Options.Create(new AuthenticationOptions { Providers = order.ToList() }));
    }

    private AuthRequest Password(string username, string password) => new()
    {
        Username = username, Method = AuthMethods.Password, Password = password, Protocol = "SSH", RemoteIp = "127.0.0.1",
        StoredUser = _repository.GetUser(username),
    };

    [Fact]
    public async Task Only_the_database_checks_the_stored_password_as_before()
    {
        var authenticator = Create([]);
        Assert.False(authenticator.HasExternalProviders);

        var ok = await authenticator.VerifyAsync(Password("local", "local-password"), TestContext.Current.CancellationToken);
        Assert.True(ok.Succeeded);
        Assert.False(ok.NeedsSave);
        Assert.Same(_repository.GetUser("local"), ok.User);

        var wrong = await authenticator.VerifyAsync(Password("local", "nope"), TestContext.Current.CancellationToken);
        Assert.Equal("wrong password", wrong.Reason);
        var unknown = await authenticator.VerifyAsync(Password("nobody", "x"), TestContext.Current.CancellationToken);
        Assert.Equal("unknown user", unknown.Reason);
    }

    [Fact]
    public void The_default_order_is_the_database_first_then_the_plug_ins()
    {
        var a = new FakeAuthenticationProvider("a", _ => AuthResult.NotHandled);
        var b = new FakeAuthenticationProvider("b", _ => AuthResult.NotHandled);
        var authenticator = new UserAuthenticator([a, new DatabaseAuthenticationProvider(_repository), b], _repository);

        Assert.Equal(["database", "a", "b"], authenticator.ProviderNames);
    }

    [Fact]
    public async Task Providers_run_in_the_configured_order_and_not_handled_asks_the_next()
    {
        var first = new FakeAuthenticationProvider("first", _ => AuthResult.NotHandled);
        var second = new FakeAuthenticationProvider("second", _ => AuthResult.Success());
        var third = new FakeAuthenticationProvider("third", _ => AuthResult.Failure("never asked"));
        var authenticator = Create([third, second, first], "first", "second", "third", "database");

        var check = await authenticator.VerifyAsync(Password("newuser", "secret"), TestContext.Current.CancellationToken);

        Assert.True(check.Succeeded);
        Assert.Equal("second", check.Provider);
        Assert.Single(first.Calls);
        Assert.Empty(third.Calls);
        Assert.True(check.NeedsSave);
        Assert.Equal("second", check.User!.AuthenticationProvider);
    }

    [Fact]
    public async Task The_first_failure_wins()
    {
        var refusing = new FakeAuthenticationProvider("refusing", _ => AuthResult.Failure("HTTP 403"));
        var accepting = new FakeAuthenticationProvider("accepting", _ => AuthResult.Success());
        var authenticator = Create([refusing, accepting], "refusing", "accepting");

        var check = await authenticator.VerifyAsync(Password("newuser", "secret"), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.Equal("HTTP 403", check.Reason);
        Assert.Empty(accepting.Calls);
    }

    [Fact]
    public async Task An_external_provider_is_never_asked_for_a_local_user()
    {
        var external = new FakeAuthenticationProvider("ldap", _ => AuthResult.Success());
        var authenticator = Create([external], "ldap", "database");

        var check = await authenticator.VerifyAsync(Password("local", "any-password"), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.Equal("wrong password", check.Reason);
        Assert.Empty(external.Calls);
    }

    [Fact]
    public async Task A_user_of_a_provider_is_never_checked_with_a_local_password()
    {
        _repository.AddUser(new User { Username = "dir-user", AuthenticationProvider = "ldap", HashedPassword = TestCredentials.HashPassword("local-password") });
        var other = new FakeAuthenticationProvider("http", _ => AuthResult.Success());
        var ldap = new FakeAuthenticationProvider("ldap", _ => AuthResult.Failure("wrong password"));
        var authenticator = Create([other, ldap]);

        var check = await authenticator.VerifyAsync(Password("dir-user", "local-password"), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.Equal("ldap", check.Provider);
        Assert.Empty(other.Calls);
    }

    [Fact]
    public async Task A_user_whose_provider_is_not_configured_is_refused()
    {
        _repository.AddUser(new User { Username = "orphan", AuthenticationProvider = "ldap" });
        var authenticator = Create([]);

        var check = await authenticator.VerifyAsync(Password("orphan", "x"), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.Equal("the authentication provider ldap of the user is not used", check.Reason);
    }

    [Fact]
    public async Task An_owner_of_the_password_only_leaves_the_stored_keys_to_the_database()
    {
        var key = TestUserKeys.Ed25519();
        var other = TestUserKeys.Ed25519();
        _repository.AddUser(new User { Username = "sso-user", AuthenticationProvider = "oidc", PublicKeys = [key.Entry] });
        var authenticator = new UserAuthenticator([new DatabaseAuthenticationProvider(_repository)], _repository,
            owners: [new CredentialOwner("oidc", OwnedCredentials.Password)]);
        AuthRequest Key(TestUserKey k) => new()
        {
            Username = "sso-user", Method = AuthMethods.PublicKey, PublicKey = k.Blob, Protocol = "SSH", RemoteIp = "127.0.0.1",
            StoredUser = _repository.GetUser("sso-user"),
        };

        var ok = await authenticator.VerifyAsync(Key(key), TestContext.Current.CancellationToken);
        Assert.True(ok.Succeeded);
        Assert.Equal("database", ok.Provider);
        Assert.False(ok.NeedsSave);
        Assert.Equal("oidc", ok.User!.AuthenticationProvider);
        Assert.False((await authenticator.VerifyAsync(Key(other), TestContext.Current.CancellationToken)).Succeeded);

        var password = await authenticator.VerifyAsync(Password("sso-user", "anything"), TestContext.Current.CancellationToken);
        Assert.False(password.Succeeded);
        Assert.Equal("the password of the user is managed by oidc", password.Reason);
    }

    [Fact]
    public async Task Without_an_ownership_rule_the_keys_of_a_provider_user_are_not_used()
    {
        var key = TestUserKeys.Ed25519();
        _repository.AddUser(new User { Username = "dir-keys", AuthenticationProvider = "ldap", PublicKeys = [key.Entry] });
        var authenticator = Create([]);

        var check = await authenticator.VerifyAsync(new AuthRequest
        {
            Username = "dir-keys", Method = AuthMethods.PublicKey, PublicKey = key.Blob, Protocol = "SSH", RemoteIp = "127.0.0.1",
            StoredUser = _repository.GetUser("dir-keys"),
        }, TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.False(CredentialOwner.IsLocal("ldap", OwnedCredentials.PublicKeys, []));
        Assert.True(CredentialOwner.IsLocal(null, OwnedCredentials.Password, []));
    }

    [Fact]
    public async Task A_provider_that_throws_refuses_the_login()
    {
        var broken = new FakeAuthenticationProvider("broken", _ => throw new InvalidOperationException("boom"));
        var accepting = new FakeAuthenticationProvider("accepting", _ => AuthResult.Success());
        var authenticator = Create([broken, accepting], "broken", "accepting");

        var check = await authenticator.VerifyAsync(Password("newuser", "secret"), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.Equal("the authentication provider broken failed", check.Reason);
        Assert.Empty(accepting.Calls);
    }

    [Fact]
    public void An_unknown_provider_name_in_the_order_stops_the_start()
    {
        var error = Assert.Throws<InvalidOperationException>(() => Create([], "database", "ldap"));
        Assert.Contains("'ldap'", error.Message);
    }

    [Fact]
    public async Task A_new_user_is_created_with_its_groups_only_when_saved()
    {
        var staff = new Group { Name = "staff", Permissions = new() { ["/"] = FilePermissions.List } };
        var readers = new Group { Name = "Readers" };
        _repository.AddGroup(staff);
        _repository.AddGroup(readers);
        var external = new FakeAuthenticationProvider("http", _ => AuthResult.Success(new ExternalUser
        {
            PrimaryGroup = "STAFF", Groups = ["readers", "missing", "staff"],
            Permissions = new Dictionary<string, FilePermissions> { ["/"] = FilePermissions.List | FilePermissions.Download },
        }));
        var authenticator = Create([external]);

        var check = await authenticator.VerifyAsync(Password("jit", "secret"), TestContext.Current.CancellationToken);

        Assert.True(check.Succeeded);
        Assert.Null(_repository.GetUser("jit")); // not before the login is complete
        Assert.Equal(staff.Id, check.User!.PrimaryGroupId);
        Assert.Equal([readers.Id], check.User.SecondaryGroupIds);
        Assert.True(authenticator.Save(check));

        var stored = _repository.GetUser("jit");
        Assert.Equal("http", stored.AuthenticationProvider);
        Assert.Null(stored.HashedPassword);
        Assert.Equal(FilePermissions.List | FilePermissions.Download, stored.Permissions!["/"]);
    }

    [Fact]
    public async Task The_next_login_updates_the_groups_and_saves_nothing_without_a_change()
    {
        _repository.AddGroup(new Group { Name = "a" });
        var b = new Group { Name = "b" };
        _repository.AddGroup(b);
        var groups = new List<string> { "a" };
        var external = new FakeAuthenticationProvider("http", _ => AuthResult.Success(new ExternalUser { PrimaryGroup = groups[0] }));
        var authenticator = Create([external]);
        Assert.True(authenticator.Save(await authenticator.VerifyAsync(Password("jit2", "secret"), TestContext.Current.CancellationToken)));

        var same = await authenticator.VerifyAsync(Password("jit2", "secret"), TestContext.Current.CancellationToken);
        Assert.False(same.NeedsSave);

        groups[0] = "b";
        var changed = await authenticator.VerifyAsync(Password("jit2", "secret"), TestContext.Current.CancellationToken);
        Assert.True(changed.NeedsSave);
        Assert.True(authenticator.Save(changed));
        Assert.Equal(b.Id, _repository.GetUser("jit2").PrimaryGroupId);
    }

    [Fact]
    public async Task A_definition_with_invalid_values_refuses_the_login()
    {
        var external = new FakeAuthenticationProvider("http", _ => AuthResult.Success(new ExternalUser
        {
            Permissions = new Dictionary<string, FilePermissions> { ["/in"] = FilePermissions.List }, // no entry for "/"
        }));
        var authenticator = Create([external]);

        var check = await authenticator.VerifyAsync(Password("jit3", "secret"), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.StartsWith("the permissions of the provider are not valid", check.Reason);
    }

    [Theory]
    [InlineData("..")]
    [InlineData("a/b")]
    [InlineData("with space")]
    public async Task A_name_that_cannot_be_a_user_is_not_created(string username)
    {
        var authenticator = Create([new FakeAuthenticationProvider("http", _ => AuthResult.Success())]);

        var check = await authenticator.VerifyAsync(Password(username, "secret"), TestContext.Current.CancellationToken);

        Assert.False(check.Succeeded);
        Assert.StartsWith("the user cannot be created", check.Reason);
    }

    [Fact]
    public async Task Save_does_not_take_over_a_local_user_created_in_the_meantime()
    {
        var authenticator = Create([new FakeAuthenticationProvider("http", _ => AuthResult.Success())]);
        var check = await authenticator.VerifyAsync(Password("race", "secret"), TestContext.Current.CancellationToken);
        _repository.AddUser(new User { Username = "race", HashedPassword = "x" });

        Assert.False(authenticator.Save(check));
        Assert.Null(_repository.GetUser("race").AuthenticationProvider);
    }

    [Fact]
    public async Task The_root_directory_of_a_new_user_is_below_the_configured_directory()
    {
        var root = Path.Combine(Path.GetTempPath(), "jit-root");
        var authenticator = new UserAuthenticator(
            [new DatabaseAuthenticationProvider(_repository), new FakeAuthenticationProvider("http", _ => AuthResult.Success())],
            _repository, Options.Create(new AuthenticationOptions { ExternalUsersRootDirectory = root }));

        var check = await authenticator.VerifyAsync(Password("rooted", "secret"), TestContext.Current.CancellationToken);

        Assert.Equal(Path.Combine(root, "rooted"), check.User!.UserRootDirectory);
    }

    [Fact]
    public async Task A_refusal_before_the_check_of_an_external_user_takes_the_time_of_its_provider()
    {
        var external = new FakeAuthenticationProvider("slow", _ =>
        {
            Thread.Sleep(150);
            return AuthResult.Failure("wrong password");
        });
        _repository.AddUser(new User { Username = "ext", AuthenticationProvider = "slow" });
        var authenticator = Create([external]);
        await authenticator.VerifyAsync(Password("ext", "wrong"), TestContext.Current.CancellationToken);

        var watch = System.Diagnostics.Stopwatch.StartNew();
        await authenticator.SpendFailureTimeAsync(Password("ext", "x"), TestContext.Current.CancellationToken);

        Assert.InRange(watch.ElapsedMilliseconds, 120, 5000);
        Assert.Single(external.Calls); // the provider is not asked again
    }

    [Fact]
    public void The_registration_reads_the_order_from_the_configuration()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Auth:Providers:0"] = "fake",
            ["Auth:Providers:1"] = "database",
        }).Build();
        var services = new ServiceCollection().AddLogging().AddSingleton<ISettingsRepository>(_repository);
        services.AddSshServerAuthentication(configuration);
        services.AddSingleton<IAuthenticationProvider>(new FakeAuthenticationProvider("fake", _ => AuthResult.NotHandled));
        using var provider = services.BuildServiceProvider();

        var authenticator = (UserAuthenticator)provider.GetRequiredService<IUserAuthenticator>();

        Assert.Equal(["fake", "database"], authenticator.ProviderNames);
        Assert.True(authenticator.HasExternalProviders);
    }
}
