using System.Net;
using System.Security.Claims;
using FreeSftpSharp.Tests.Infrastructure;
using FxSsh.SshServerModule.Security;
using FxSshSftpServer.Security;
using FxSshSftpServer.Security.Oidc;
using FxSshSftpServer.WebClient;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Users;
using SshServerModule.Authentication;

namespace FreeSftpSharp.Tests.Oidc;

internal static class OidcPrincipal
{
    public static ClaimsPrincipal Of(string? username, string[]? roles = null, string[]? groups = null)
    {
        var claims = new List<Claim> { new("sub", Guid.NewGuid().ToString("N")) };
        if (username != null)
            claims.Add(new Claim("preferred_username", username));
        claims.AddRange((roles ?? []).Select(r => new Claim("roles", r)));
        claims.AddRange((groups ?? []).Select(g => new Claim("groups", g)));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "OidcTest"));
    }
}

/// <summary>The local user of a web client sign-in (#73): ownership, provisioning with the groups (#64), the local rules.</summary>
public sealed class ClientOidcAccountsTests : IDisposable
{
    private static readonly IPAddress Client = IPAddress.Parse("192.0.2.10");

    private readonly InMemorySettingsRepository _repository = new(new ServerSettings());
    private readonly string _root = Path.Combine(Path.GetTempPath(), "fss-oidc-" + Guid.NewGuid().ToString("N"));
    private readonly Group _template;
    private readonly Group _staff;

    public ClientOidcAccountsTests()
    {
        _repository.AddGroup(new Group { Name = "partners", Permissions = new() { ["/"] = FilePermissions.List | FilePermissions.Download } });
        _repository.AddGroup(new Group { Name = "staff" });
        _template = _repository.GetGroups().Single(g => g.Name == "partners");
        _staff = _repository.GetGroups().Single(g => g.Name == "staff");
        _repository.AddUser(new User { Username = "local", HashedPassword = TestCredentials.HashPassword("local-password"), UserRootDirectory = _root });
        _repository.AddUser(new User { Username = "ldap-user", AuthenticationProvider = "ldap", UserRootDirectory = _root });
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);
    }

    private ClientOidcAccounts Create(Action<ClientOidcOptions>? change = null)
    {
        var options = new ClientOidcOptions { Authority = "https://idp.test", ClientId = "client", TemplateGroup = "partners" };
        change?.Invoke(options);
        var logins = new PasswordLoginService(_repository, new LoginBanTracker(TimeProvider.System), NullLogger<PasswordLoginService>.Instance);
        return new ClientOidcAccounts(Options.Create(options), _repository, new ExternalUserProvisioner(_repository, _root),
            new EffectiveUserSettingsService(_repository), logins, TimeProvider.System, NullLogger<ClientOidcAccounts>.Instance);
    }

    [Fact]
    public void A_new_user_is_refused_without_auto_provisioning()
    {
        var result = Create().Resolve(OidcPrincipal.Of("newcomer"), Client);

        Assert.Equal(OidcRefusal.UnknownAccount, result.Refusal);
        Assert.Null(_repository.GetUser("newcomer"));
    }

    [Fact]
    public void Auto_provisioning_creates_an_oidc_user_without_password_in_the_template_and_mapped_groups()
    {
        var result = Create(o => o.AutoProvision = true).Resolve(OidcPrincipal.Of("newcomer", groups: ["/staff", "unknown"]), Client);

        Assert.Equal(OidcRefusal.None, result.Refusal);
        var stored = _repository.GetUser("newcomer");
        Assert.NotNull(stored);
        Assert.Equal(OidcClaims.ProviderName, stored.AuthenticationProvider);
        Assert.Null(stored.HashedPassword);
        Assert.Equal(OidcClaims.ProviderName, ExternalCredentials.PasswordManagedBy(stored));
        Assert.Equal(_template.Id, stored.PrimaryGroupId);
        Assert.Equal([_staff.Id], stored.SecondaryGroupIds);
        Assert.Equal(Path.Combine(_root, "newcomer"), stored.UserRootDirectory);
        Assert.True(Directory.Exists(stored.UserRootDirectory));
    }

    [Fact]
    public void The_next_sign_in_follows_the_groups_of_the_token_and_keeps_the_primary_group()
    {
        var accounts = Create(o => o.AutoProvision = true);
        accounts.Resolve(OidcPrincipal.Of("mover", groups: ["staff"]), Client);

        var result = accounts.Resolve(OidcPrincipal.Of("mover"), Client);

        Assert.Equal(OidcRefusal.None, result.Refusal);
        var stored = _repository.GetUser("mover")!;
        Assert.Empty(stored.SecondaryGroupIds ?? []);
        Assert.Equal(_template.Id, stored.PrimaryGroupId);
    }

    [Fact]
    public void A_local_user_signs_in_as_itself_and_is_not_changed()
    {
        var result = Create(o => o.AutoProvision = true).Resolve(OidcPrincipal.Of("local", groups: ["staff"]), Client);

        Assert.Equal(OidcRefusal.None, result.Refusal);
        var stored = _repository.GetUser("local")!;
        Assert.Null(stored.AuthenticationProvider);
        Assert.NotNull(stored.HashedPassword);
        Assert.Empty(stored.SecondaryGroupIds ?? []);
    }

    [Fact]
    public void A_user_of_another_provider_is_refused()
    {
        var result = Create(o => o.AutoProvision = true).Resolve(OidcPrincipal.Of("ldap-user"), Client);

        Assert.Equal(OidcRefusal.AccountNotUsable, result.Refusal);
        Assert.Equal("ldap", _repository.GetUser("ldap-user")!.AuthenticationProvider);
    }

    [Fact]
    public void Without_the_required_role_nothing_is_created()
    {
        var accounts = Create(o =>
        {
            o.AutoProvision = true;
            o.RequiredRoleValue = "sftp-user";
        });

        Assert.Equal(OidcRefusal.MissingRole, accounts.Resolve(OidcPrincipal.Of("norole", roles: ["other"]), Client).Refusal);
        Assert.Null(_repository.GetUser("norole"));
        Assert.Equal(OidcRefusal.None, accounts.Resolve(OidcPrincipal.Of("withrole", roles: ["sftp-user"]), Client).Refusal);
    }

    [Fact]
    public void A_token_without_the_username_claim_is_refused()
    {
        Assert.Equal(OidcRefusal.NoUsername, Create().Resolve(OidcPrincipal.Of(null), Client).Refusal);
    }

    [Fact]
    public void The_local_rules_still_apply()
    {
        _repository.AddUser(new User { Username = "disabled", Status = UserStatus.Disabled, UserRootDirectory = _root });
        _repository.AddUser(new User { Username = "sftponly", AllowedProtocols = UserProtocols.Sftp, UserRootDirectory = _root });
        _repository.AddUser(new User { Username = "office", OnlyWhitelistedIps = true, WhitelistedIps = ["10.0.0.0/8"], UserRootDirectory = _root });
        var accounts = Create();

        Assert.Equal(OidcRefusal.AccountRefused, accounts.Resolve(OidcPrincipal.Of("disabled"), Client).Refusal);
        Assert.Equal(OidcRefusal.AccountRefused, accounts.Resolve(OidcPrincipal.Of("sftponly"), Client).Refusal);
        Assert.Equal(OidcRefusal.AccountRefused, accounts.Resolve(OidcPrincipal.Of("office"), Client).Refusal);
        Assert.Equal(OidcRefusal.None, accounts.Resolve(OidcPrincipal.Of("office"), IPAddress.Parse("10.1.2.3")).Refusal);
    }

    [Fact]
    public void A_name_that_is_not_a_valid_user_name_is_not_created()
    {
        var result = Create(o => o.AutoProvision = true).Resolve(OidcPrincipal.Of("bad/name"), Client);

        Assert.Equal(OidcRefusal.AccountNotUsable, result.Refusal);
    }

    [Fact]
    public void A_banned_address_is_refused_first()
    {
        var settings = _repository.ServerSettings;
        settings.BlacklistedIps = ["192.0.2.0/24"];
        _repository.UpdateServerSettings(settings);

        Assert.Equal(OidcRefusal.AddressRefused, Create().Resolve(OidcPrincipal.Of("local"), Client).Refusal);
    }
}

/// <summary>The administrator of an admin UI sign-in (#73): must exist, or is created with the permissions of its roles (#60).</summary>
public sealed class AdminOidcAccountsTests
{
    private readonly InMemoryAdminStore _store = new();
    private readonly InMemorySettingsRepository _repository = new(new ServerSettings());

    private AdminOidcAccounts Create(Action<AdminOidcOptions>? change = null)
    {
        var options = new AdminOidcOptions
        {
            Authority = "https://idp.test", ClientId = "admin",
            RolePermissions = new() { ["helpdesk"] = "ViewConnections, ViewAudit", ["usermanager"] = "ManageUsers", ["root"] = "SuperAdmin" },
        };
        change?.Invoke(options);
        return new AdminOidcAccounts(Options.Create(options), _store,
            new AdminAdministrationService(_store, _repository, hashIterations: PasswordHasherIterations), NullLogger<AdminOidcAccounts>.Instance);
    }

    private const int PasswordHasherIterations = SshServer.Interfaces.Security.PasswordHasher.MinimumIterations;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task An_existing_administrator_signs_in()
    {
        await _store.AddAdminAsync(new Admin { Username = "alice", PasswordHash = "x", Permissions = AdminPermissions.SuperAdmin }, Ct);

        var result = await Create().ResolveAsync(OidcPrincipal.Of("alice"), IPAddress.Loopback, Ct);

        Assert.Equal("alice", result.Account?.Username);
    }

    [Fact]
    public async Task An_unknown_administrator_is_refused_without_auto_provisioning()
    {
        var result = await Create().ResolveAsync(OidcPrincipal.Of("mallory", roles: ["root"]), IPAddress.Loopback, Ct);

        Assert.Equal(OidcRefusal.UnknownAccount, result.Refusal);
        Assert.Null(await _store.GetAdminAsync("mallory", Ct));
    }

    [Fact]
    public async Task Auto_provisioning_gives_the_union_of_the_role_permissions_and_no_usable_password()
    {
        var result = await Create(o => o.AutoProvision = true)
            .ResolveAsync(OidcPrincipal.Of("bob", roles: ["helpdesk", "usermanager", "unmapped"]), IPAddress.Loopback, Ct);

        var admin = Assert.IsType<Admin>(result.Account);
        Assert.Equal(AdminPermissions.ViewConnections | AdminPermissions.ViewAudit | AdminPermissions.ManageUsers, admin.Permissions);
        Assert.Null(admin.ScopeRoleId);
        Assert.False(admin.MustChangePassword);
        Assert.NotNull(await _store.GetAdminAsync("bob", Ct));
    }

    [Fact]
    public async Task A_role_value_that_names_a_scope_role_becomes_the_scope()
    {
        var role = new Role { Name = "tenant-a" };
        await _store.AddRoleAsync(role, Ct);

        var result = await Create(o => o.AutoProvision = true)
            .ResolveAsync(OidcPrincipal.Of("carol", roles: ["usermanager", "tenant-a"]), IPAddress.Loopback, Ct);

        Assert.Equal(role.Id, result.Account?.ScopeRoleId);
    }

    [Fact]
    public async Task Auto_provisioning_without_a_mapped_role_is_refused()
    {
        var result = await Create(o => o.AutoProvision = true).ResolveAsync(OidcPrincipal.Of("dave", roles: ["unmapped"]), IPAddress.Loopback, Ct);

        Assert.Equal(OidcRefusal.MissingRole, result.Refusal);
        Assert.Null(await _store.GetAdminAsync("dave", Ct));
    }

    [Fact]
    public async Task The_required_role_is_checked_also_for_an_existing_administrator()
    {
        await _store.AddAdminAsync(new Admin { Username = "erin", PasswordHash = "x", Permissions = AdminPermissions.SuperAdmin }, Ct);
        var accounts = Create(o => o.RequiredRoleValue = "sftp-admin");

        Assert.Equal(OidcRefusal.MissingRole, (await accounts.ResolveAsync(OidcPrincipal.Of("erin"), IPAddress.Loopback, Ct)).Refusal);
        Assert.Equal("erin", (await accounts.ResolveAsync(OidcPrincipal.Of("erin", roles: ["sftp-admin"]), IPAddress.Loopback, Ct)).Account?.Username);
    }

    [Fact]
    public async Task A_disabled_administrator_or_another_network_is_refused()
    {
        await _store.AddAdminAsync(new Admin { Username = "off", PasswordHash = "x", Status = AdminStatus.Disabled, Permissions = AdminPermissions.SuperAdmin }, Ct);
        await _store.AddAdminAsync(new Admin { Username = "lan", PasswordHash = "x", AllowedIps = ["10.0.0.0/8"], Permissions = AdminPermissions.SuperAdmin }, Ct);
        var accounts = Create();

        Assert.Equal(OidcRefusal.AccountRefused, (await accounts.ResolveAsync(OidcPrincipal.Of("off"), IPAddress.Loopback, Ct)).Refusal);
        Assert.Equal(OidcRefusal.AccountRefused, (await accounts.ResolveAsync(OidcPrincipal.Of("lan"), IPAddress.Parse("192.0.2.1"), Ct)).Refusal);
        Assert.Equal("lan", (await accounts.ResolveAsync(OidcPrincipal.Of("lan"), IPAddress.Parse("10.0.0.1"), Ct)).Account?.Username);
    }
}
