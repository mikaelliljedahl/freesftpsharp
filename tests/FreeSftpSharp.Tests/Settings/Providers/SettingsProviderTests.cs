using FreeSftpSharp.Tests.Infrastructure;
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
}
