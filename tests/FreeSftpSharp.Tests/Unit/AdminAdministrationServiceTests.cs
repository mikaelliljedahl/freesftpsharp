using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.Infrastructure;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>The rules for administrators and scope roles (#60): validation, no privilege escalation, events.</summary>
public sealed class AdminAdministrationServiceTests
{
    private const string Password = "long-enough-1";

    private readonly InMemoryAdminStore _store = new();
    private readonly InMemorySettingsRepository _settings = new(new ServerSettings());
    private readonly RecordingEventBus _events = new();
    private readonly AdminAdministrationService _service;

    public AdminAdministrationServiceTests()
    {
        _service = new AdminAdministrationService(_store, _settings, _events, hashIterations: PasswordHasher.MinimumIterations);
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static AdminActor Super(string name = "root") => new(name, AdminPermissionRules.Everything, null);

    private Task<Admin> CreateAsync(string name, AdminPermissions permissions, int? scope = null, AdminActor? actor = null) =>
        _service.CreateAdminAsync(actor ?? AdminActor.System, new AdminInput(name) { Permissions = permissions, ScopeRoleId = scope }, Password, Ct);

    [Fact]
    public async Task A_new_administrator_is_stored_with_a_pbkdf2_hash_and_an_add_event_without_secrets()
    {
        var admin = await CreateAsync("alice", AdminPermissions.ManageUsers | AdminPermissions.ViewAudit, actor: Super());

        var stored = await _store.GetAdminAsync("ALICE", Ct);
        Assert.NotNull(stored);
        Assert.Equal(admin.Id, stored.Id);
        Assert.True(PasswordHasher.Verify(Password, stored.PasswordHash));
        Assert.DoesNotContain(Password, stored.PasswordHash);

        var @event = Assert.IsType<ProviderEvent>(Assert.Single(_events.Published));
        Assert.Equal((ProviderAction.Add, ProviderObjectType.Admin, "alice", "root"), (@event.Action, @event.ObjectType, @event.ObjectName, @event.Actor));
        var snapshot = Assert.IsType<AdminSnapshot>(@event.Object);
        Assert.Equal("ManageUsers, ViewAudit", snapshot.Permissions);
        Assert.DoesNotContain(snapshot.GetType().GetProperties(), p => p.Name.Contains("Password", StringComparison.Ordinal) && p.PropertyType == typeof(string));
    }

    [Theory]
    [InlineData("", Password, "Enter a user name.")]
    [InlineData("with space", Password, "spaces")]
    [InlineData("bob", "short", "at least 8")]
    public async Task Invalid_input_is_refused(string name, string password, string message)
    {
        var ex = await Assert.ThrowsAsync<AdminAdministrationException>(() =>
            _service.CreateAdminAsync(AdminActor.System, new AdminInput(name), password, Ct));

        Assert.Contains(message, ex.Message);
        Assert.False(await _store.AnyAdminAsync(Ct));
    }

    [Fact]
    public async Task A_name_is_used_once_without_case()
    {
        await CreateAsync("alice", AdminPermissions.ManageUsers);

        var ex = await Assert.ThrowsAsync<AdminAdministrationException>(() => CreateAsync("ALICE", AdminPermissions.ManageUsers));
        Assert.Contains("already exists", ex.Message);
    }

    [Fact]
    public async Task Invalid_allowed_networks_are_refused()
    {
        var ex = await Assert.ThrowsAsync<AdminAdministrationException>(() =>
            _service.CreateAdminAsync(AdminActor.System, new AdminInput("bob") { AllowedIps = ["10.0.0.0/8", "not-a-network"] }, Password, Ct));

        Assert.Contains("not-a-network", ex.Message);
    }

    [Fact]
    public async Task Without_manage_admins_nothing_can_be_listed_or_changed()
    {
        var actor = new AdminActor("users-only", AdminPermissions.ManageUsers, null);

        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => _service.ListAdminsAsync(actor, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => CreateAsync("bob", AdminPermissions.ManageUsers, actor: actor));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => _service.CreateRoleAsync(actor, "tenant-a", null, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => _service.ListRolesAsync(actor, Ct));
    }

    [Fact]
    public async Task An_administrator_cannot_grant_permissions_it_does_not_have()
    {
        var manager = new AdminActor("manager", AdminPermissions.ManageAdmins | AdminPermissions.ManageUsers, null);

        await CreateAsync("helper", AdminPermissions.ManageUsers, actor: manager);
        var ex = await Assert.ThrowsAsync<AdminAccessDeniedException>(() => CreateAsync("boss", AdminPermissions.SuperAdmin, actor: manager));
        Assert.Contains("SuperAdmin", ex.Message);
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => CreateAsync("settings", AdminPermissions.ManageSettings, actor: manager));
    }

    [Fact]
    public async Task An_administrator_cannot_change_or_remove_an_administrator_with_more_permissions()
    {
        await CreateAsync("root", AdminPermissions.SuperAdmin);
        var manager = new AdminActor("manager", AdminPermissions.ManageAdmins | AdminPermissions.ManageUsers, null);

        await Assert.ThrowsAsync<AdminAccessDeniedException>(() =>
            _service.UpdateAdminAsync(manager, new AdminInput("root") { Permissions = AdminPermissions.ManageUsers }, "new-password-1", Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => _service.DeleteAdminAsync(manager, "root", Ct));
        Assert.Equal(AdminPermissions.SuperAdmin, (await _store.GetAdminAsync("root", Ct))!.Permissions);
    }

    [Fact]
    public async Task Nobody_changes_its_own_permissions_or_status_or_removes_itself()
    {
        await CreateAsync("root", AdminPermissions.SuperAdmin);
        var self = Super("root");

        await Assert.ThrowsAsync<AdminAccessDeniedException>(() =>
            _service.UpdateAdminAsync(self, new AdminInput("root") { Permissions = AdminPermissions.ManageUsers }, null, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() =>
            _service.UpdateAdminAsync(self, new AdminInput("root") { Permissions = AdminPermissions.SuperAdmin, Status = AdminStatus.Disabled }, null, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => _service.DeleteAdminAsync(self, "root", Ct));

        // The own e-mail address may change.
        var updated = await _service.UpdateAdminAsync(self, new AdminInput("root") { Permissions = AdminPermissions.SuperAdmin, Email = "root@example.org" }, null, Ct);
        Assert.Equal("root@example.org", updated.Email);
    }

    [Fact]
    public async Task A_scoped_administrator_has_only_scopable_permissions_and_no_super_admin()
    {
        var role = await _service.CreateRoleAsync(Super(), "tenant-a", null, Ct);

        await Assert.ThrowsAsync<AdminAdministrationException>(() => CreateAsync("a1", AdminPermissions.SuperAdmin, role.Id));
        await Assert.ThrowsAsync<AdminAdministrationException>(() => CreateAsync("a2", AdminPermissions.ManageUsers | AdminPermissions.ManageSettings, role.Id));
        await Assert.ThrowsAsync<AdminAdministrationException>(() => CreateAsync("a3", AdminPermissions.ManageUsers, role.Id + 100));

        var scoped = await CreateAsync("a4", AdminPermissions.ManageUsers | AdminPermissions.ViewAudit, role.Id);
        Assert.Equal(role.Id, scoped.ScopeRoleId);
    }

    [Fact]
    public void Effective_permissions_mask_a_scope_a_disabled_account_and_a_pending_password_change()
    {
        Assert.Equal(AdminPermissionRules.Everything, AdminPermissionRules.Effective(new Admin { Permissions = AdminPermissions.SuperAdmin }));
        Assert.Equal(AdminPermissions.ManageUsers,
            AdminPermissionRules.Effective(new Admin { Permissions = AdminPermissions.ManageUsers | AdminPermissions.ManageSettings | AdminPermissions.SuperAdmin, ScopeRoleId = 1 }));
        Assert.Equal(AdminPermissions.None, AdminPermissionRules.Effective(new Admin { Permissions = AdminPermissions.SuperAdmin, Status = AdminStatus.Disabled }));
        Assert.Equal(AdminPermissions.None, AdminPermissionRules.Effective(new Admin { Permissions = AdminPermissions.SuperAdmin, MustChangePassword = true }));
    }

    [Fact]
    public async Task An_update_publishes_the_changed_fields_and_a_new_password_without_the_hash()
    {
        await CreateAsync("bob", AdminPermissions.ManageUsers);
        var before = _events.Published.Count;

        await _service.UpdateAdminAsync(Super(), new AdminInput("bob") { Permissions = AdminPermissions.ManageUsers | AdminPermissions.ViewAudit }, "other-password-2", Ct);

        var @event = Assert.IsType<ProviderEvent>(Assert.Single(_events.Published.Skip(before)));
        Assert.Equal(ProviderAction.Update, @event.Action);
        Assert.Equal(["Permissions", "Password"], @event.ChangedFields);
        Assert.True(PasswordHasher.Verify("other-password-2", (await _store.GetAdminAsync("bob", Ct))!.PasswordHash));
    }

    [Fact]
    public async Task The_own_password_changes_only_with_the_current_one_and_clears_the_must_change_flag()
    {
        await _service.CreateAdminAsync(AdminActor.System, new AdminInput("bob") { Permissions = AdminPermissions.ManageUsers, MustChangePassword = true }, Password, Ct);

        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => _service.ChangeOwnPasswordAsync("bob", "wrong", "new-password-3", Ct));
        await Assert.ThrowsAsync<AdminAdministrationException>(() => _service.ChangeOwnPasswordAsync("bob", Password, Password, Ct));

        var changed = await _service.ChangeOwnPasswordAsync("bob", Password, "new-password-3", Ct);
        Assert.False(changed.MustChangePassword);
        Assert.True(PasswordHasher.Verify("new-password-3", (await _store.GetAdminAsync("bob", Ct))!.PasswordHash));
    }

    [Fact]
    public async Task The_configured_account_is_imported_once_as_super_admin()
    {
        var hash = PasswordHasher.Hash("configured-1", PasswordHasher.MinimumIterations);

        Assert.True(await _service.ImportConfiguredAdminAsync(" admin ", hash, Ct));
        Assert.False(await _service.ImportConfiguredAdminAsync("other", hash, Ct));

        var admin = Assert.Single(await _store.ListAdminsAsync(Ct));
        Assert.Equal("admin", admin.Username);
        Assert.Equal(hash, admin.PasswordHash);
        Assert.Equal(AdminPermissionRules.Everything, AdminPermissionRules.Effective(admin));
        var @event = Assert.IsType<ProviderEvent>(Assert.Single(_events.Published));
        Assert.Equal("system", @event.Actor);
    }

    [Fact]
    public async Task A_role_in_use_cannot_be_deleted()
    {
        var role = await _service.CreateRoleAsync(Super(), "tenant-a", "Tenant A", Ct);
        _settings.AddUser(new User { Username = "u1", RoleId = role.Id });
        await CreateAsync("scoped", AdminPermissions.ManageUsers, role.Id);

        var ex = await Assert.ThrowsAsync<AdminAdministrationException>(() => _service.DeleteRoleAsync(Super(), role.Id, Ct));
        Assert.Contains("1 user(s) and 1 administrator(s)", ex.Message);

        _settings.GetUser("u1").RoleId = null;
        await _service.DeleteAdminAsync(Super(), "scoped", Ct);
        await _service.DeleteRoleAsync(Super(), role.Id, Ct);
        Assert.Empty(await _store.ListRolesAsync(Ct));
    }

    [Fact]
    public async Task Role_names_are_unique_without_case()
    {
        await _service.CreateRoleAsync(Super(), "tenant-a", null, Ct);

        await Assert.ThrowsAsync<AdminAdministrationException>(() => _service.CreateRoleAsync(Super(), "TENANT-A", null, Ct));
        await Assert.ThrowsAsync<AdminAdministrationException>(() => _service.CreateRoleAsync(Super(), " ", null, Ct));
    }
}
