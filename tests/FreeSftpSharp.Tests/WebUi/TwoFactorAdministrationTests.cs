using Bunit;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using FxSshSftpServer.Components.Pages;
using FxSshSftpServer.Security;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.TwoFactor;
using SshServer.TwoFactor;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>
/// The second factor in the admin UI (#63): an administrator sets up its own app with the QR code and gets the recovery
/// codes once; it sets up and resets the app of a user in its scope; it resets (but never sets up) the second factor of
/// another administrator with no more permissions. Turning off its own second factor needs a current code.
/// </summary>
public sealed class TwoFactorAdministrationTests : AdminUiComponentContext
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    private readonly TempDirectory _root = new();

    public TwoFactorAdministrationTests()
    {
        AddAdmin("admin", AdminPermissions.SuperAdmin);
    }

    private static CancellationToken Ct => Xunit.TestContext.Current.CancellationToken;

    private TwoFactorAdministration Administration2Fa => Services.GetRequiredService<TwoFactorAdministration>();

    private Admin AddAdmin(string name, AdminPermissions permissions, int? scope = null)
    {
        var admin = new Admin { Username = name, PasswordHash = "x", Permissions = permissions, ScopeRoleId = scope };
        Assert.True(AdminStore.AddAdminAsync(admin, CancellationToken.None).GetAwaiter().GetResult());
        return admin;
    }

    private User AddUser(string name, int? role = null)
    {
        var user = new User { Username = name, UserRootDirectory = _root.Path, RoleId = role, WhitelistedIps = new List<string>() };
        Repository.AddUser(user);
        return user;
    }

    private string Now(string secret) => TwoFactorTestKit.Code(secret, Clock.GetUtcNow());

    [Fact]
    public async Task An_administrator_sets_up_its_own_app_and_sees_the_recovery_codes_once()
    {
        var page = Render<AccountTwoFactor>();
        page.WaitForElement("#two-factor-off");

        page.Click("#two-factor-setup");
        page.WaitForElement("#two-factor-qr svg");
        var secret = page.Find("#two-factor-secret").TextContent.Replace(" ", "");
        page.Change("#two-factor-confirm-code", Now(secret));
        page.Click("#two-factor-confirm");

        page.WaitForAssertion(() => Assert.Equal(10, page.FindAll(".recovery-code").Count), Timeout);
        var admin = (await AdminStore.GetAdminAsync("admin", Ct))!;
        Assert.True(await TwoFactor.IsEnabledAsync(TwoFactorSubject.ForAdmin(admin), Ct));
        Assert.Contains(Events.Published.OfType<ProviderEvent>(),
            e => e.ObjectType == ProviderObjectType.Admin && e.ObjectName == "admin" && e.ChangedFields.Contains("TwoFactor") && e.Actor == "admin");

        page.Click("#recovery-codes-done");
        page.WaitForElement("#two-factor-on");
        Assert.Empty(page.FindAll(".recovery-code"));
    }

    [Fact]
    public async Task A_wrong_confirmation_code_leaves_the_second_factor_off()
    {
        var page = Render<AccountTwoFactor>();
        page.WaitForElement("#two-factor-setup");
        page.Click("#two-factor-setup");
        page.WaitForElement("#two-factor-qr svg");

        page.Change("#two-factor-confirm-code", "000000");
        page.Click("#two-factor-confirm");

        page.WaitForElement("#two-factor-error");
        Assert.Empty(await TwoFactorStore.ListEnabledAsync(TwoFactorSubjectKind.Admin, Ct));
    }

    [Fact]
    public async Task Turning_off_the_own_second_factor_needs_a_current_code()
    {
        var admin = (await AdminStore.GetAdminAsync("admin", Ct))!;
        var (secret, _) = await TwoFactorTestKit.EnrolAsync(TwoFactor, TwoFactorSubject.ForAdmin(admin), Clock);
        var self = Administration2Fa.Self;

        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => Administration2Fa.ResetAsync(self, null, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => Administration2Fa.ResetAsync(self, "000000", Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => Administration2Fa.RegenerateRecoveryCodesAsync(self, null, Ct));
        Assert.True(await TwoFactor.IsEnabledAsync(TwoFactorSubject.ForAdmin(admin), Ct));

        Assert.True(await Administration2Fa.ResetAsync(self, Now(secret), Ct));
        Assert.False(await TwoFactor.IsEnabledAsync(TwoFactorSubject.ForAdmin(admin), Ct));
    }

    [Fact]
    public async Task An_administrator_sets_up_and_resets_the_app_of_a_user()
    {
        var user = AddUser("alice");
        var target = TwoFactorTarget.User("alice");

        var setup = await Administration2Fa.BeginSetupAsync(target, Ct);
        Assert.Contains(":alice?", setup.OtpAuthUri);
        Assert.NotNull(await Administration2Fa.ConfirmSetupAsync(target, Now(setup.SecretBase32), Ct));
        Assert.True(await TwoFactor.IsEnabledAsync(TwoFactorSubject.ForUser(user), Ct));

        Assert.True(await Administration2Fa.ResetAsync(target, null, Ct)); // no code needed for another account
        Assert.False(await TwoFactor.IsEnabledAsync(TwoFactorSubject.ForUser(user), Ct));
        Assert.Equal(2, Events.Published.OfType<ProviderEvent>().Count(e => e.ObjectType == ProviderObjectType.User && e.ObjectName == "alice"));
    }

    [Fact]
    public async Task The_users_page_shows_the_second_factor_and_resets_it()
    {
        var user = AddUser("alice");
        AddUser("bob");
        await TwoFactorTestKit.EnrolAsync(TwoFactor, TwoFactorSubject.ForUser(user), Clock);

        var page = Render<Users>();
        page.WaitForAssertion(() => Assert.Single(page.FindAll("#user-table .badge"), b => b.TextContent == "2FA"));

        PageEvents.Trigger(() => page.FindAll(".edit-user").First(b => b.GetAttribute("aria-label") == "Edit alice"), e => e.Click());
        page.WaitForElement("#two-factor-on");
        page.Click("#two-factor-reset");
        page.Click(".confirm-button");

        page.WaitForElement("#two-factor-off", Timeout);
        Assert.False(await TwoFactor.IsEnabledAsync(TwoFactorSubject.ForUser(user), Ct));
        page.WaitForAssertion(() => Assert.DoesNotContain(page.FindAll("#user-table .badge"), b => b.TextContent == "2FA"));
    }

    [Fact]
    public async Task A_scoped_administrator_cannot_touch_a_user_of_another_role()
    {
        var role = new Role { Name = "tenant-a" };
        Assert.True(await AdminStore.AddRoleAsync(role, Ct));
        var other = new Role { Name = "tenant-b" };
        Assert.True(await AdminStore.AddRoleAsync(other, Ct));
        var outside = AddUser("b-user", other.Id);
        await TwoFactorTestKit.EnrolAsync(TwoFactor, TwoFactorSubject.ForUser(outside), Clock);
        AddUser("a-user", role.Id);
        SignInAs(AdminPermissions.ManageUsers, role.Id, "tenant-admin");

        await Assert.ThrowsAsync<AdminAdministrationException>(() => Administration2Fa.ResetAsync(TwoFactorTarget.User("b-user"), null, Ct));
        await Assert.ThrowsAsync<AdminAdministrationException>(() => Administration2Fa.BeginSetupAsync(TwoFactorTarget.User("b-user"), Ct));
        Assert.True(await TwoFactor.IsEnabledAsync(TwoFactorSubject.ForUser(outside), Ct));
        Assert.Equal(TwoFactorState.Off, (await Administration2Fa.GetStatusAsync(TwoFactorTarget.User("a-user"), Ct)).State);
    }

    [Fact]
    public async Task Without_the_users_permission_the_second_factor_of_a_user_is_closed()
    {
        AddUser("alice");
        SignInAs(AdminPermissions.ViewAudit, name: "auditor");

        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => Administration2Fa.GetStatusAsync(TwoFactorTarget.User("alice"), Ct));
    }

    [Fact]
    public async Task Another_administrator_can_be_reset_but_never_set_up()
    {
        var other = AddAdmin("helper", AdminPermissions.ManageUsers);
        await TwoFactorTestKit.EnrolAsync(TwoFactor, TwoFactorSubject.ForAdmin(other), Clock);
        var target = TwoFactorTarget.Admin("helper");

        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => Administration2Fa.BeginSetupAsync(target, Ct));
        Assert.True(await Administration2Fa.ResetAsync(target, null, Ct));
        Assert.False(await TwoFactor.IsEnabledAsync(TwoFactorSubject.ForAdmin(other), Ct));
    }

    [Fact]
    public async Task An_administrator_cannot_reset_one_with_more_permissions()
    {
        var super = AddAdmin("root", AdminPermissions.SuperAdmin);
        await TwoFactorTestKit.EnrolAsync(TwoFactor, TwoFactorSubject.ForAdmin(super), Clock);
        AddAdmin("manager", AdminPermissions.ManageAdmins);
        SignInAs(AdminPermissions.ManageAdmins, name: "manager");

        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => Administration2Fa.ResetAsync(TwoFactorTarget.Admin("root"), null, Ct));
        Assert.True(await TwoFactor.IsEnabledAsync(TwoFactorSubject.ForAdmin(super), Ct));
    }
}
