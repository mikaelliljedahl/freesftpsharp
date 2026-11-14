using Bunit;
using FxSshSftpServer.Components.Pages;
using SshServer.Interfaces;
using SshServer.Interfaces.Shares;
using SharesPage = FxSshSftpServer.Components.Pages.Shares;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>The admin page of the share links (#70) and the share settings of the server settings page.</summary>
public sealed class SharesPageTests : AdminUiComponentContext
{
    private async Task<Share> AddShareAsync(string username)
    {
        var share = new Share { Id = ShareId.New(), UserId = 1, Username = username, Name = "Reports of " + username, Paths = ["/out"], CreatedAt = DateTime.UtcNow };
        await Shares.AddAsync(share, CancellationToken.None);
        return share;
    }

    [Fact]
    public async Task The_page_lists_the_shares_and_revokes_one_after_confirmation()
    {
        var revoked = await AddShareAsync("alice");
        var kept = await AddShareAsync("bob");
        var page = Render<SharesPage>();
        Assert.Equal("2", page.Find("#admin-share-count").TextContent);

        page.Find($"tr[data-share-id='{revoked.Id}'] .revoke-share").Click();
        page.Find(".confirm-button").Click();

        Assert.Null(await Shares.GetAsync(revoked.Id, CancellationToken.None));
        Assert.NotNull(await Shares.GetAsync(kept.Id, CancellationToken.None));
        Assert.Single(page.FindAll(".admin-share-row"));
        Assert.Contains(Toasts.Messages, m => m.Text.Contains("alice"));
    }

    [Fact]
    public void The_settings_page_turns_the_share_links_on_with_their_limits()
    {
        var page = Render<ServerSettingsPage>();
        Assert.False(page.Find("#shares-enabled").HasAttribute("checked"));

        page.Find("#shares-enabled").Change(true);
        page.Find("#share-max-lifetime").Change("30");
        page.Find("#share-require-password").Change(true);
        page.Find("#server-settings-form").Submit();

        Assert.Equal(new ShareSettings { Enabled = true, MaxLifetimeDays = 30, RequirePassword = true }, Repository.ServerSettings.Shares);
    }
}
