using FreeSftpSharp.Tests.EventRules;
using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.EventRules;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// The server with the event rules plug-in (AddSshServerEvents + AddEventRules) on the local disk storage, and the rule
/// "on an upload to /incoming/* by test_person: move the file to /processed/{{Name}}, then send an email". The mail
/// server is a fake. The test user may not write to /processed itself: the action is a server operation.
/// </summary>
public sealed class EventRuleServerFixture : SftpServerFixture
{
    public const string OtherUser = "other_person";
    public const string OtherPassword = "other-password";

    private readonly DeferredFileSystemFactory _files = new();

    public EventRuleTestHost Rules { get; private set; } = null!;

    public int RuleId { get; private set; }

    public override async ValueTask InitializeAsync()
    {
        Rules = new EventRuleTestHost(files: _files, configure: services =>
            // The users of the SSH server (an in-memory repository of the fixture, created at the start).
            services.Replace(ServiceDescriptor.Singleton<ISettingsRepository>(_ => Repository)));
        await base.InitializeAsync();
        AddUser(OtherUser, TestCredentials.HashPassword(OtherPassword));
        Directory.CreateDirectory(PhysicalPath("/incoming"));

        RuleId = await Rules.AddRuleAsync(new EventRuleInput
        {
            Name = "process incoming",
            Trigger = EventRuleTrigger.Event,
            EventTypes = ["File.Upload"],
            Conditions = new EventRuleConditions { Users = [Username], PathGlob = "/incoming/*" },
            Actions =
            [
                new EventRuleAction { Type = "Move", Options = new() { ["Target"] = "/processed/{{Name}}" }, StopOnFailure = true },
                new EventRuleAction
                {
                    Type = "Email",
                    Options = new() { ["To"] = "ops@example.com", ["Subject"] = "{{Username}} uploaded {{Name}}", ["Body"] = "{{FileSize}} bytes" },
                },
            ],
        });
        await Rules.StartAsync();
    }

    protected override void ConfigureUser(User user)
        => user.Permissions = new() { ["/"] = FilePermissions.All, ["/processed"] = FilePermissions.List | FilePermissions.Download };

    protected override IEventBus CreateEventBus() => Rules.Bus;

    protected override IFileSystemFactory CreateFileSystemFactory(IConnectionRegistry connections, IEventBus? events)
    {
        var factory = new StorageFileSystemFactory(new StorageProviderRegistry([new LocalDiskStorageProvider()]), new UserRootStorageResolver(),
            new EffectivePermissionsService(), connections, events);
        _files.Inner = factory;
        return factory;
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        await Rules.DisposeAsync();
    }

    /// <summary>The storage of the SSH server, given to the rules engine once the server has it.</summary>
    private sealed class DeferredFileSystemFactory : IFileSystemFactory
    {
        public IFileSystemFactory? Inner { get; set; }

        public ValueTask<IFileSystem> CreateAsync(User user, ClientContext client, CancellationToken ct)
            => (Inner ?? throw new InvalidOperationException("The server is not started.")).CreateAsync(user, client, ct);
    }
}

/// <summary>Event rules on real SFTP sessions (#68): an upload starts a rule that moves the file and sends an email.</summary>
public sealed class EventRuleEndToEndTests : IClassFixture<EventRuleServerFixture>
{
    private readonly EventRuleServerFixture _server;

    public EventRuleEndToEndTests(EventRuleServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task An_upload_to_incoming_is_moved_to_processed_and_mailed_and_an_upload_of_another_user_is_not()
    {
        var name = $"report-{Guid.NewGuid():N}.csv";
        var otherName = $"other-{Guid.NewGuid():N}.csv";

        using (var other = _server.CreateClient(EventRuleServerFixture.OtherPassword, EventRuleServerFixture.OtherUser))
        {
            other.Connect();
            using var stream = new MemoryStream(new byte[100]);
            other.UploadFile(stream, "/incoming/" + otherName);
        }
        using (var client = _server.Connect())
        {
            using var stream = new MemoryStream(new byte[1234]);
            client.UploadFile(stream, "/incoming/" + name);
        }

        var runs = await _server.Rules.WaitForRunsAsync(_server.RuleId, r => r.Any(run => run.Message.Contains(name)));
        var run = runs.Single(r => r.Message.Contains(name));
        Assert.Equal(EventRuleRunStatus.Ok, run.Status);
        Assert.Equal(_server.Username, run.Username);

        using (var client = _server.Connect())
        {
            Assert.True(client.Exists("/processed/" + name));
            Assert.False(client.Exists("/incoming/" + name));
            Assert.Equal(1234, client.GetAttributes("/processed/" + name).Size);
            // The upload of the other user stays where it is.
            Assert.True(client.Exists("/incoming/" + otherName));
        }
        var mail = Assert.Single(_server.Rules.Emails.Sent, m => m.Subject.Contains(name));
        Assert.Equal($"{_server.Username} uploaded {name}", mail.Subject);
        Assert.Equal("1234 bytes", mail.Body);
        Assert.DoesNotContain(_server.Rules.Emails.Sent, m => m.Subject.Contains(otherName));
    }
}
