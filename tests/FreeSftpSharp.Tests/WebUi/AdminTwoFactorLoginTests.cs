using System.Net;
using System.Text.RegularExpressions;
using FreeSftpSharp.Tests.Infrastructure;
using FxSshSftpServer.Pages;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.TwoFactor;
using SshServer.TwoFactor;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>
/// The admin login with a second factor (#63): after the right password an administrator with TOTP gets the code page,
/// not the login cookie; a wrong or reused code is refused, a recovery code works once, and an administrator without
/// TOTP logs in with the password as before. Each test has its own administrator, so the per-administrator code limit
/// of one test does not touch another.
/// </summary>
[Collection(AdminUiCollection.Name)]
public sealed partial class AdminTwoFactorLoginTests : IClassFixture<AdminUiFactory>
{
    private const string Password = "Another-Horse-42";
    private static readonly string PasswordHash = PasswordHasher.Hash(Password, PasswordHasher.MinimumIterations);

    private readonly AdminUiFactory _factory;

    public AdminTwoFactorLoginTests(AdminUiFactory factory)
    {
        _factory = factory;
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private TwoFactorService TwoFactor => _factory.Services.GetRequiredService<TwoFactorService>();

    /// <summary>Adds a super admin with a confirmed second factor; returns its name, secret and recovery codes.</summary>
    private async Task<(string Name, string Secret, IReadOnlyList<string> RecoveryCodes)> AddAdminWithTotpAsync()
    {
        var name = await AddAdminAsync();
        var admin = (await _factory.AdminStore.GetAdminAsync(name, Ct))!;
        var (secret, codes) = await TwoFactorTestKit.EnrolAsync(TwoFactor, TwoFactorSubject.ForAdmin(admin), TimeProvider.System, name);
        return (name, secret, codes);
    }

    private async Task<string> AddAdminAsync()
    {
        _ = _factory.Services; // start the host first: it imports the configured admin into an empty store
        var name = "totp-" + Guid.NewGuid().ToString("N")[..8];
        Assert.True(await _factory.AdminStore.AddAdminAsync(new Admin
        {
            Username = name,
            PasswordHash = PasswordHash,
            Permissions = AdminPermissions.SuperAdmin,
        }, Ct));
        return name;
    }

    private static string CurrentCode(string secret) => TwoFactorTestKit.Code(secret, DateTimeOffset.UtcNow);

    private static bool HasLoginCookie(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var cookies)
        && cookies.Any(c => c.StartsWith(".FxSshSftpServer.Admin=", StringComparison.Ordinal) && !c.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));

    private static async Task<HttpResponseMessage> SubmitCodeAsync(HttpClient browser, string code, string? returnUrl = null)
    {
        var url = returnUrl is null ? "/LoginCode" : "/LoginCode?ReturnUrl=" + Uri.EscapeDataString(returnUrl);
        var page = await browser.GetAsync(url, Ct);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var token = WebUtility.HtmlDecode(TokenRegex().Match(await page.Content.ReadAsStringAsync(Ct)).Groups[1].Value);
        return await browser.PostAsync(url, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Code"] = code,
            ["__RequestVerificationToken"] = token,
        }), Ct);
    }

    [Fact]
    public async Task An_administrator_with_totp_needs_the_code_after_the_password()
    {
        var (name, secret, _) = await AddAdminWithTotpAsync();
        using var browser = _factory.CreateBrowser();

        var login = await AdminUiAuthenticationTests.LogInAsync(browser, name, Password);

        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.Equal("/LoginCode", login.Headers.Location!.OriginalString);
        Assert.False(HasLoginCookie(login));
        var home = await browser.GetAsync("/", Ct);
        Assert.Equal(HttpStatusCode.Redirect, home.StatusCode); // the password alone gives no access
        Assert.Equal("/Login", home.Headers.Location!.AbsolutePath);

        var wrong = await SubmitCodeAsync(browser, "000000");
        Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
        Assert.Contains(LoginCodeModel.InvalidCodeMessage, await wrong.Content.ReadAsStringAsync(Ct));
        Assert.False(HasLoginCookie(wrong));

        var right = await SubmitCodeAsync(browser, CurrentCode(secret));
        Assert.Equal(HttpStatusCode.Redirect, right.StatusCode);
        Assert.Equal("/", right.Headers.Location!.OriginalString);
        Assert.True(HasLoginCookie(right));
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/", Ct)).StatusCode);
    }

    [Fact]
    public async Task The_return_url_is_kept_through_the_code_step()
    {
        var (name, secret, _) = await AddAdminWithTotpAsync();
        using var browser = _factory.CreateBrowser();

        var login = await AdminUiAuthenticationTests.LogInAsync(browser, name, Password, returnUrl: "/general");
        Assert.Equal("/LoginCode?ReturnUrl=%2Fgeneral", login.Headers.Location!.OriginalString);

        var right = await SubmitCodeAsync(browser, CurrentCode(secret), "/general");
        Assert.Equal("/general", right.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task A_code_works_for_one_login_only()
    {
        var (name, secret, _) = await AddAdminWithTotpAsync();
        var code = CurrentCode(secret);

        using (var first = _factory.CreateBrowser())
        {
            await AdminUiAuthenticationTests.LogInAsync(first, name, Password);
            Assert.True(HasLoginCookie(await SubmitCodeAsync(first, code)));
        }

        using var second = _factory.CreateBrowser();
        await AdminUiAuthenticationTests.LogInAsync(second, name, Password);
        var again = await SubmitCodeAsync(second, code);
        Assert.False(HasLoginCookie(again));
        Assert.Contains(LoginCodeModel.InvalidCodeMessage, await again.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task A_recovery_code_works_once()
    {
        var (name, _, recovery) = await AddAdminWithTotpAsync();

        using (var first = _factory.CreateBrowser())
        {
            await AdminUiAuthenticationTests.LogInAsync(first, name, Password);
            Assert.True(HasLoginCookie(await SubmitCodeAsync(first, recovery[0])));
        }

        using var second = _factory.CreateBrowser();
        await AdminUiAuthenticationTests.LogInAsync(second, name, Password);
        Assert.False(HasLoginCookie(await SubmitCodeAsync(second, recovery[0])));
    }

    [Fact]
    public async Task The_code_page_without_the_password_step_goes_back_to_the_login()
    {
        using var browser = _factory.CreateBrowser();

        var page = await browser.GetAsync("/LoginCode", Ct);

        Assert.Equal(HttpStatusCode.Redirect, page.StatusCode);
        Assert.Equal("/Login", page.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task A_wrong_password_never_reaches_the_code_step()
    {
        var (name, _, _) = await AddAdminWithTotpAsync();
        using var browser = _factory.CreateBrowser();

        var login = await AdminUiAuthenticationTests.LogInAsync(browser, name, "wrong-password");

        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync("/LoginCode", Ct)).StatusCode);
    }

    [Fact]
    public async Task After_a_reset_the_password_alone_logs_in_again()
    {
        var (name, _, _) = await AddAdminWithTotpAsync();
        var admin = (await _factory.AdminStore.GetAdminAsync(name, Ct))!;
        Assert.True(await TwoFactor.ResetAsync(TwoFactorSubject.ForAdmin(admin), Ct));
        using var browser = _factory.CreateBrowser();

        var login = await AdminUiAuthenticationTests.LogInAsync(browser, name, Password);

        Assert.Equal("/", login.Headers.Location!.OriginalString);
        Assert.True(HasLoginCookie(login));
    }

    [Fact]
    public async Task An_administrator_without_totp_logs_in_with_the_password_alone()
    {
        var name = await AddAdminAsync();
        using var browser = _factory.CreateBrowser();

        var login = await AdminUiAuthenticationTests.LogInAsync(browser, name, Password);

        Assert.Equal("/", login.Headers.Location!.OriginalString);
        Assert.True(HasLoginCookie(login));
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex TokenRegex();
}
