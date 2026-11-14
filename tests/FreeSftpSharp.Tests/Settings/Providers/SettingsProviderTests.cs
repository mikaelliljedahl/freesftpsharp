using Microsoft.EntityFrameworkCore.Infrastructure;
using System.Net;
using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces.Cluster;
using SshServer.Interfaces.Connections;
using SshServer.Settings.Sql.Cluster;
using SshServer.Settings.Sql.Database;
using Microsoft.EntityFrameworkCore;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Api;
using SshServer.Interfaces.Audit;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.TwoFactor;
using SshServer.Interfaces.Webhooks;
using SshServer.Interfaces.Security;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.Admins;
using SshServer.Settings.Sql.Api;
using SshServer.Settings.Sql.Audit;
using SshServer.Settings.Sql.EventRules;
using SshServer.Settings.Sql.Quotas;
using SshServer.Settings.Sql.TwoFactor;
using SshServer.Settings.Sql.Webhooks;

namespace FreeSftpSharp.Tests.Settings.Providers;

/// <summary>
/// The settings repository and the stores on every settings database provider (#75): SQLite always, PostgreSQL and SQL
/// Server when their server is configured (<see cref="TestDatabase"/>). The behaviour that depends on the database is
/// here: the migrations, the JSON columns, the names without case, the dates, and the conditional updates of the
/// shared state of several nodes.
/// </summary>
public sealed class SettingsProviderTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly DateTime Now = new(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);

    private static SqlSettingsRepository Repository(TestDatabase db) => new(db.Options, createHostKey: () => TestCredentials.HostKey);

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_new_database_is_migrated_and_gets_the_default_settings(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);

        Assert.Equal(TestCredentials.HostKey, repository.ServerSettings.ServerRsaKey);
        Assert.Equal(22, repository.ServerSettings.ListenToPort);
        await using var context = new SettingsDbContext(db.Options);
        Assert.Empty(await context.Database.GetPendingMigrationsAsync(Ct));
        Assert.False(context.Database.HasPendingModelChanges());

        // A second start on the same database migrates nothing and keeps the settings.
        using var again = Repository(db);
        Assert.Equal(TestCredentials.HostKey, again.ServerSettings.ServerRsaKey);
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_database_refuses_a_second_row_of_server_settings(string provider)
    {
        // Two nodes on an empty database both insert the settings (#149): only the first row is accepted.
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);
        await using var context = new SettingsDbContext(db.Options);
        context.ServerSettings.Add(new ServerSettings { ServerRsaKey = "another-node-key", ListenToPort = 22 });

        Assert.Throws<DbUpdateException>(() => context.SaveChanges());

        Assert.Equal(TestCredentials.HostKey, Repository(db).ServerSettings.ServerRsaKey);
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_database_with_two_rows_of_server_settings_keeps_the_first_at_the_upgrade(string provider)
    {
        // Before #149 two nodes on an empty database could both insert the settings; every read took the lowest id.
        await using var db = await TestDatabase.CreateAsync(provider);
        await using (var context = new SettingsDbContext(db.Options))
        {
            var before = context.Database.GetMigrations().SkipLast(1).Last();
            Assert.EndsWith("_SingleServerSettingsRow", context.Database.GetMigrations().Last());
            await context.GetService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>().MigrateAsync(before, cancellationToken: Ct);
            foreach (var key in new[] { "first-key", "second-key" })
                await context.Database.ExecuteSqlRawAsync(
                    "INSERT INTO \"ServerSettings\" (\"ServerRsaKey\", \"ListenToPort\", \"OnlyWhitelistedIps\", \"MaxLoginAttemptsBeforeBan\", " +
                    "\"LoginFailureWindowSeconds\", \"BanDurationSeconds\", \"ExemptLoopbackFromBan\", \"PasswordMaxAgeDays\", \"IdleTimeout\", " +
                    "\"EnableCommand\", \"EnableDirectTcpIp\") VALUES ({0}, 22, {1}, 0, 600, 1800, {2}, 0, 600, {1}, {1})",
                    [key, false, true], Ct);
        }

        using var repository = new SqlSettingsRepository(db.Options, createHostKey: () => throw new InvalidOperationException("must not be called"));

        Assert.Equal("first-key", repository.ServerSettings.ServerRsaKey);
        await using var after = new SettingsDbContext(db.Options);
        Assert.Equal(1, await after.ServerSettings.CountAsync(Ct));
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_AdminAuth_import_of_two_nodes_at_the_same_time_keeps_one_admin_without_an_error(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);
        var hash = PasswordHasher.Hash("Admin-Pass-1", PasswordHasher.MinimumIterations);
        // Node B checks that there is no administrator; node A stores its import just before B saves (#149).
        var otherNode = new AdminAdministrationService(new SqlAdminStore(db.Options), repository);
        var options = new DbContextOptionsBuilder<SettingsDbContext>(db.Options)
            .AddInterceptors(new BeforeFirstSave(() => Assert.True(otherNode.ImportConfiguredAdminAsync("admin", hash, Ct).GetAwaiter().GetResult())))
            .Options;
        var store = new SqlAdminStore(options);

        Assert.False(await new AdminAdministrationService(store, repository).ImportConfiguredAdminAsync("admin", hash, Ct));

        Assert.Equal(["admin"], (await store.ListAdminsAsync(Ct)).Select(a => a.Username));
    }

    /// <summary>Runs an action once, just before the first SaveChanges of a context on these options.</summary>
    private sealed class BeforeFirstSave(Action action) : Microsoft.EntityFrameworkCore.Diagnostics.SaveChangesInterceptor
    {
        private int _done;

        public override ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int>> SavingChangesAsync(
            Microsoft.EntityFrameworkCore.Diagnostics.DbContextEventData eventData, Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Exchange(ref _done, 1) == 0)
                action();
            return ValueTask.FromResult(result);
        }
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_node_that_connected_before_another_node_migrated_the_database_works(string provider)
    {
        // Node B connects to the empty database first (PostgreSQL then loads the types without citext) ...
        await using var db = await TestDatabase.CreateAsync(provider);
        await using (var context = new SettingsDbContext(db.Options))
            Assert.Empty(await context.Database.GetAppliedMigrationsAsync(Ct));
        // ... node A migrates it, with a connection of its own (another connection string: another Npgsql data source) ...
        var builder = new DbContextOptionsBuilder<SettingsDbContext>();
        db.Provider.Configure(builder, OtherNode(provider, db.ConnectionString));
        using (new SqlSettingsRepository(builder.Options, createHostKey: () => TestCredentials.HostKey))
        {
        }

        // ... and node B starts on it: names without case (citext on PostgreSQL) work.
        using var nodeB = Repository(db);
        Assert.True(nodeB.AddUser(new User { Username = "Carol", HashedPassword = "x" }));
        Assert.Equal("Carol", nodeB.GetUser("carol")?.Username);
    }

    private static string OtherNode(string provider, string connectionString) => provider switch
    {
        "PostgreSQL" => connectionString + ";Application Name=other-node",
        "SqlServer" => connectionString + ";Application Name=other-node",
        _ => connectionString,
    };

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_ecdsa_host_key_of_the_first_node_wins_and_the_other_node_gets_it(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var nodeA = Repository(db);
        using var nodeB = Repository(db);
        var seenByA = nodeA.ServerSettings; // node A read the settings without an ECDSA key ...
        Assert.Null(seenByA.ServerEcdsaKey);

        Assert.Equal("key-of-b", nodeB.EnsureServerEcdsaKey("key-of-b")); // ... node B stores its key first ...

        Assert.Equal("key-of-b", nodeA.EnsureServerEcdsaKey("key-of-a")); // ... and node A gets the key of B, not its own
        Assert.Equal("key-of-b", Repository(db).ServerSettings.ServerEcdsaKey);
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_user_keeps_every_field_and_is_found_without_case(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);
        var user = new User
        {
            Username = "Bob",
            UserRootDirectory = "/srv/bob",
            HashedPassword = TestCredentials.HashPassword("secret"),
            OnlyWhitelistedIps = true,
            WhitelistedIps = ["10.0.0.0/8", "192.168.1.5"],
            LastLoginAt = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc),
            ExpiresAt = new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Unspecified),
            Permissions = new Dictionary<string, FilePermissions> { ["/"] = FilePermissions.All, ["/in"] = FilePermissions.Upload },
            AllowedAuthMethods = AuthMethods.Password | AuthMethods.PublicKey,
            RequireAllOf = [AuthMethods.PublicKey, AuthMethods.Password],
            DiskQuota = new DiskQuota { MaxSizeBytes = 1000, MaxFiles = 10 },
            Description = "Bob's account",
            SecondaryGroupIds = [],
        };

        Assert.True(repository.AddUser(user));
        Assert.False(repository.AddUser(new User { Username = "BOB" }));

        var stored = repository.GetUser("bob");
        Assert.NotNull(stored);
        Assert.Equal("Bob", stored.Username);
        Assert.Equal(user.WhitelistedIps, stored.WhitelistedIps);
        Assert.Equal(user.LastLoginAt, stored.LastLoginAt);
        Assert.Equal(user.ExpiresAt, stored.ExpiresAt);
        Assert.Equal(FilePermissions.Upload, stored.Permissions!["/in"]);
        Assert.Equal(user.AllowedAuthMethods, stored.AllowedAuthMethods);
        Assert.Equal(user.RequireAllOf, stored.RequireAllOf);
        Assert.Equal(1000, stored.DiskQuota!.MaxSizeBytes);

        stored.Description = "changed";
        Assert.True(repository.UpdateUser(stored));
        Assert.Equal("changed", repository.GetUser("BOB").Description);
        Assert.True(repository.RemoveUser("bOb"));
        Assert.Null(repository.GetUser("Bob"));
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Groups_and_mounted_folders_are_stored_and_a_removed_folder_is_unmounted(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);
        var folder = new VirtualFolder { Name = "Shared", Storage = new StorageConfig { Provider = "local", Options = "{\"Root\":\"/srv/shared\"}" } };
        Assert.True(repository.AddVirtualFolder(folder));
        Assert.False(repository.AddVirtualFolder(new VirtualFolder { Name = "shared", Storage = folder.Storage }));
        var group = new Group { Name = "Staff", VirtualFolders = [new VirtualFolderMount { VirtualFolderId = folder.Id, MountPath = "/shared" }] };
        Assert.True(repository.AddGroup(group));
        Assert.False(repository.AddGroup(new Group { Name = "STAFF" }));
        Assert.True(repository.AddUser(new User
        {
            Username = "carol", PrimaryGroupId = group.Id, SecondaryGroupIds = [],
            VirtualFolders = [new VirtualFolderMount { VirtualFolderId = folder.Id, MountPath = "/data" }],
        }));

        Assert.False(repository.RemoveGroup(group.Id)); // it has a member
        Assert.True(repository.RemoveVirtualFolder(folder.Id));

        Assert.Empty(repository.GetUser("carol").VirtualFolders);
        Assert.Empty(repository.GetGroup(group.Id)!.VirtualFolders);
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Administrators_roles_and_api_keys_are_stored_and_found_without_case(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);
        var admins = new SqlAdminStore(db.Options);
        var role = new Role { Name = "Tenant-A" };
        Assert.True(await admins.AddRoleAsync(role, Ct));
        var admin = new Admin
        {
            Username = "Alice", PasswordHash = "x", Permissions = AdminPermissions.ManageUsers | AdminPermissions.ViewAudit,
            ScopeRoleId = role.Id, AllowedIps = ["10.0.0.0/8"],
        };
        Assert.True(await admins.AddAdminAsync(admin, Ct));
        Assert.False(await admins.AddAdminAsync(new Admin { Username = "ALICE", PasswordHash = "y" }, Ct));
        Assert.Equal(admin.Permissions, (await admins.GetAdminAsync("alice", Ct))!.Permissions);
        Assert.Null((await admins.GetAdminAsync("alice", Ct))!.AuthenticationProvider);
        admin.AuthenticationProvider = "oidc"; // #145
        Assert.True(await admins.UpdateAdminAsync(admin, Ct));
        Assert.Equal("oidc", (await admins.GetAdminAsync("alice", Ct))!.AuthenticationProvider);

        var keys = new SqlApiKeyStore(db.Options);
        var key = new ApiKey { Name = "ci", Prefix = "fss_abc", KeyHash = new string('a', 64), AdminId = admin.Id, CreatedAt = Now };
        Assert.True(await keys.AddAsync(key, Ct));
        Assert.False(await keys.AddAsync(new ApiKey { Name = "CI", Prefix = "fss_def", KeyHash = new string('b', 64), AdminId = admin.Id, CreatedAt = Now }, Ct));
        Assert.Equal(key.Id, (await keys.FindByHashAsync(new string('a', 64), Ct))!.Id);

        // The token signing key is created once and is the same for every node.
        var first = await keys.GetOrAddAsync(() => "key-1", Ct);
        var second = await new SqlApiKeyStore(db.Options).GetOrAddAsync(() => "key-2", Ct);
        Assert.Equal("key-1", first);
        Assert.Equal("key-1", second);

        Assert.True(await admins.RemoveAdminAsync(admin.Id, Ct));
        Assert.Null(await keys.GetAsync(key.Id, Ct)); // removed with its administrator
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Quota_counters_are_increments_that_add_up_across_nodes(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);
        var nodeA = new SqlQuotaUsageStore(db.Options);
        var nodeB = new SqlQuotaUsageStore(db.Options);
        var scope = QuotaScope.ForUser("dave");

        await nodeA.AddAsync(scope, new QuotaUsageDelta(100, 1, 100, 0), Now, Ct);
        var usage = await nodeB.AddAsync(scope, new QuotaUsageDelta(50, 1, 0, 20), Now.AddSeconds(1), Ct);

        Assert.Equal(150, usage.UsedBytes);
        Assert.Equal(2, usage.UsedFiles);
        Assert.Equal(100, usage.UploadedBytes);
        Assert.Equal(20, usage.DownloadedBytes);
        var reset = await nodeA.ResetTransferAsync(scope, Now.AddSeconds(2), Ct);
        Assert.Equal(0, reset.UploadedBytes);
        Assert.Equal(150, reset.UsedBytes);
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_webhook_delivery_is_claimed_by_one_node_until_its_lease_ends(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);
        var store = new SqlWebhookStore(db.Options);
        var webhook = new Webhook { Name = "Audit", Url = "https://example.org/hook", EventTypes = ["File.Upload"] };
        Assert.True(await store.AddAsync(webhook, Ct));
        Assert.False(await store.AddAsync(new Webhook { Name = "audit", Url = "https://example.org/other" }, Ct));
        await store.AddDeliveriesAsync([new WebhookDelivery
        {
            DeliveryId = Guid.NewGuid(), WebhookId = webhook.Id, EventId = Guid.NewGuid(), EventType = "File.Upload",
            Payload = "{}", Status = WebhookDeliveryStatus.Pending, CreatedUtc = Now, NextAttemptUtc = Now,
        }], Ct);

        var first = await store.ClaimDueAsync("node-a", Now, Now.AddMinutes(2), 10, Ct);
        var second = await new SqlWebhookStore(db.Options).ClaimDueAsync("node-b", Now.AddMinutes(1), Now.AddMinutes(3), 10, Ct);
        var afterLease = await store.ClaimDueAsync("node-b", Now.AddMinutes(3), Now.AddMinutes(5), 10, Ct);

        Assert.Equal("node-a", Assert.Single(first).LeaseOwner);
        Assert.Empty(second);
        Assert.Equal("node-b", Assert.Single(afterLease).LeaseOwner);
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_scheduled_rule_occurrence_is_claimed_once(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);
        var store = new SqlEventRuleStore(db.Options);
        var rule = new EventRule
        {
            Name = "Nightly", Trigger = EventRuleTrigger.Schedule, CronExpression = "0 3 * * *",
            Actions = [new EventRuleAction { Type = "QuotaScan", Options = new() { ["Users"] = "*" } }],
        };
        Assert.True(await store.AddAsync(rule, Ct));

        Assert.True(await store.TryClaimScheduledRunAsync(rule.Id, Now, Ct));
        Assert.False(await new SqlEventRuleStore(db.Options).TryClaimScheduledRunAsync(rule.Id, Now, Ct));
        Assert.True(await store.TryClaimScheduledRunAsync(rule.Id, Now.AddDays(1), Ct));
        Assert.Equal("QuotaScan", (await store.GetAsync(rule.Id, Ct))!.Actions.Single().Type);
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_two_factor_enrolment_is_updated_only_from_its_current_version(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);
        Assert.True(repository.AddUser(new User { Username = "erin", SecondaryGroupIds = [] }));
        var subject = TwoFactorSubject.ForUser(repository.GetUser("erin"));
        var store = new SqlTwoFactorStore(db.Options);

        var enrolment = await store.ReplaceAsync(new TwoFactorEnrolment
        {
            Subject = subject, ProtectedSecret = "protected", Enabled = true, RecoveryCodeHashes = ["h1", "h2"], CreatedAt = Now,
        }, Ct);

        Assert.True(await store.TryUpdateAsync(enrolment with { LastUsedStep = 10 }, Ct));
        Assert.False(await store.TryUpdateAsync(enrolment with { LastUsedStep = 11 }, Ct)); // the old version: another node was first
        var stored = await store.GetAsync(subject, Ct);
        Assert.Equal(10, stored!.LastUsedStep);
        Assert.Equal(["h1", "h2"], stored.RecoveryCodeHashes);
        Assert.Contains(subject.Id, await store.ListEnabledAsync(TwoFactorSubjectKind.User, Ct));
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_audit_log_is_queried_without_case_and_old_entries_are_removed(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);
        var log = new SqlAuditLog(db.Options);
        await log.AppendAsync(new AuditEntry { TimestampUtc = Now.AddDays(-100), Category = "Auth", Type = "LoginOk", Status = "Ok", Username = "Frank" }, Ct);
        await log.AppendAsync(new AuditEntry { TimestampUtc = Now, Category = "Auth", Type = "LoginFailed", Status = "Error", Username = "frank" }, Ct);

        var result = await log.QueryAsync(new AuditQuery { Username = "FRANK" }, Ct);
        Assert.Equal(2, result.TotalCount);
        Assert.Equal("LoginFailed", result.Entries[0].Type); // newest first

        Assert.Equal(1, await log.DeleteOlderThanAsync(Now.AddDays(-90), Ct));
        Assert.Equal(1, (await log.QueryAsync(new AuditQuery(), Ct)).TotalCount);
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Shared_bans_are_stored_listed_lifted_and_expire(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);
        var store = new SqlIpBanStore(db.Options);
        var now = new DateTimeOffset(Now);
        await store.AddAsync(new IpBan(IPAddress.Parse("203.0.113.7"), now, now.AddMinutes(10), 5), Ct);
        await store.AddAsync(new IpBan(IPAddress.Parse("2001:db8::7"), now, now.AddMinutes(1), 3), Ct);
        await store.AddAsync(new IpBan(IPAddress.Parse("203.0.113.7"), now, now.AddMinutes(20), 6), Ct); // replaces

        var active = await new SqlIpBanStore(db.Options).ListActiveAsync(now.AddMinutes(5), Ct);
        var ban = Assert.Single(active);
        Assert.Equal(IPAddress.Parse("203.0.113.7"), ban.Address);
        Assert.Equal(now.AddMinutes(20), ban.ExpiresAt);
        Assert.Equal(6, ban.FailedAttempts);

        Assert.Equal(1, await store.RemoveExpiredAsync(now.AddMinutes(5), Ct));
        await store.RemoveAsync(IPAddress.Parse("203.0.113.7"), Ct);
        Assert.Empty(await store.ListActiveAsync(now, Ct));
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Nodes_store_their_connections_take_their_disconnect_requests_and_stale_nodes_are_removed(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);
        var store = new SqlClusterStore(db.Options);
        var now = new DateTimeOffset(Now);
        var connection = new ConnectionInfo(Guid.NewGuid(), ConnectionProtocols.Sftp, "203.0.113.7:50123", "SSH-2.0-Test", now.AddMinutes(-1),
            now, "Grace", now.AddSeconds(-50), "password",
            [new ActiveTransfer(Guid.NewGuid(), "/in/file.bin", TransferDirection.Upload, 4096, now.AddSeconds(-5))]);

        await store.HeartbeatAsync(new NodeInfo("node-a", "host-a", "1.0", now.AddHours(-1), now), [connection], Ct);
        await store.HeartbeatAsync(new NodeInfo("node-b", "host-b", "1.0", now.AddHours(-1), now.AddMinutes(-10)), [connection with { Id = Guid.NewGuid() }], Ct);

        var listed = Assert.Single(await store.ListConnectionsAsync(now.AddMinutes(-1), Ct)); // node-b is not alive
        Assert.Equal(connection.Id, listed.Id);
        Assert.Equal("node-a", listed.Node);
        Assert.Equal("Grace", listed.Username);
        Assert.Equal(connection.AuthenticatedAt, listed.AuthenticatedAt);
        Assert.Equal(4096, Assert.Single(listed.Transfers).Bytes);

        // The next heartbeat replaces the connections of the node.
        await store.HeartbeatAsync(new NodeInfo("node-a", "host-a", "1.0", now.AddHours(-1), now.AddSeconds(5)), [], Ct);
        Assert.Empty(await store.ListConnectionsAsync(now.AddMinutes(-1), Ct));

        await store.RequestDisconnectAsync("node-a", connection.Id, "Closed by node B.", now, Ct);
        var request = Assert.Single(await store.TakeDisconnectRequestsAsync("node-a", Ct));
        Assert.Equal(connection.Id, request.ConnectionId);
        Assert.Equal("Closed by node B.", request.Reason);
        Assert.Empty(await store.TakeDisconnectRequestsAsync("node-a", Ct));

        Assert.Equal(1, await store.RemoveStaleNodesAsync(now.AddMinutes(-1), Ct));
        Assert.Equal("node-a", Assert.Single(await store.ListNodesAsync(Ct)).NodeId);
        await store.RemoveNodeAsync("node-a", Ct);
        Assert.Empty(await store.ListNodesAsync(Ct));
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_settings_version_grows_with_every_change(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);
        var nodeA = new SqlClusterStore(db.Options);
        var nodeB = new SqlClusterStore(db.Options);

        Assert.Equal(0, await nodeA.GetAsync(Ct));
        await nodeA.BumpAsync(Ct);
        await nodeB.BumpAsync(Ct);
        await Task.WhenAll(nodeA.BumpAsync(Ct), nodeB.BumpAsync(Ct));

        Assert.Equal(4, await nodeB.GetAsync(Ct));
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Data_protection_keys_in_the_database_are_shared_by_the_nodes(string provider)
    {
        await using var db = await TestDatabase.CreateAsync(provider);
        using var repository = Repository(db);

        string protectedText;
        using (var nodeA = DataProtection(db))
            protectedText = nodeA.GetRequiredService<IDataProtectionProvider>().CreateProtector("test").Protect("secret");
        using var nodeB = DataProtection(db);

        Assert.Equal("secret", nodeB.GetRequiredService<IDataProtectionProvider>().CreateProtector("test").Unprotect(protectedText));
        await using var context = new SettingsDbContext(db.Options);
        Assert.Equal(1, await context.DataProtectionKeys.CountAsync(Ct));
    }

    private static ServiceProvider DataProtection(TestDatabase db)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddSingleton<ISettingsRepository>(_ => new SqlSettingsRepository(db.Options, createHostKey: () => TestCredentials.HostKey));
        services.AddSingleton(new SettingsDatabase(db.ProviderName, db.Options));
        services.AddDataProtection().SetApplicationName("FreeSftpSharp.Tests").PersistKeysToSettingsDatabase();
        return services.BuildServiceProvider();
    }
}
