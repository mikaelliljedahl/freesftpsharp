using Bunit;
using ConnectionsPage = FxSshSftpServer.Components.Pages.Connections;
using SshServer.Interfaces.Connections;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>The Connections page: the open connections with their transfers, auto refresh, disconnect after confirmation.</summary>
public sealed class ConnectionsPageTests : AdminUiComponentContext
{
    private static readonly TimeSpan RefreshInterval = ConnectionsPage.RefreshInterval;
    private readonly List<string> _disconnected = new();

    private ConnectionInfo Connect(string endPoint, string? username = null)
    {
        var connection = Registry.Register(new ConnectionRegistration(ConnectionProtocols.Sftp, endPoint, reason =>
        {
            _disconnected.Add(endPoint + " " + reason);
            return Task.CompletedTask;
        }));
        if (username != null)
            Registry.SetAuthenticated(connection.Id, username, "password");
        return connection;
    }

    [Fact]
    public void No_connection_shows_an_empty_note()
    {
        var page = Render<ConnectionsPage>();

        Assert.NotNull(page.Find("#no-connections"));
        Assert.Equal("0", page.Find("#connection-count").TextContent);
    }

    [Fact]
    public void The_connections_are_listed_with_user_address_and_transfers()
    {
        var alice = Connect("192.0.2.1:40000", "alice");
        Connect("192.0.2.2:40001");
        var progress = Registry.BeginTransfer(alice.Id, "/up/report.pdf", TransferDirection.Upload);
        progress.AddBytes(3 * 1024 * 1024);

        var page = Render<ConnectionsPage>();

        var rows = page.FindAll(".connection-row");
        Assert.Equal(2, rows.Count);
        Assert.Contains("alice", rows[0].QuerySelector(".connection-user")!.TextContent);
        Assert.Equal("192.0.2.1:40000", rows[0].QuerySelector(".connection-endpoint")!.TextContent);
        Assert.Contains("/up/report.pdf", rows[0].QuerySelector(".connection-transfers")!.TextContent);
        Assert.Equal("3.0 MiB", rows[0].QuerySelector(".transfer-bytes")!.TextContent);
        Assert.Contains("not logged in", rows[1].QuerySelector(".connection-user")!.TextContent);
    }

    [Fact]
    public void The_list_refreshes_by_itself()
    {
        var page = Render<ConnectionsPage>();
        Assert.NotNull(page.Find("#no-connections"));

        var bob = Connect("192.0.2.3:40002", "bob");
        var progress = Registry.BeginTransfer(bob.Id, "/big.iso", TransferDirection.Download);
        progress.AddBytes(100);
        Clock.Advance(RefreshInterval);

        page.WaitForAssertion(() => Assert.Equal("100 B", page.Find(".transfer-bytes").TextContent));

        progress.AddBytes(1000);
        Clock.Advance(RefreshInterval);

        page.WaitForAssertion(() => Assert.Equal("1.1 KiB", page.Find(".transfer-bytes").TextContent));
    }

    [Fact]
    public void Disconnect_asks_for_confirmation_and_cancel_keeps_the_connection()
    {
        Connect("192.0.2.4:40003", "carol");
        var page = Render<ConnectionsPage>();

        page.Click(".disconnect-button");
        Assert.Contains("carol", page.Find(".modal").TextContent);
        page.Click(".modal .btn-secondary");

        Assert.Empty(page.FindAll(".modal"));
        Assert.Empty(_disconnected);
        Assert.Single(Registry.GetAll());
    }

    [Fact]
    public void Disconnect_closes_the_connection_after_confirmation()
    {
        Connect("192.0.2.5:40004", "dave");
        var keep = Connect("192.0.2.6:40005", "erin");
        var page = Render<ConnectionsPage>();

        page.Click(".disconnect-button", 0);
        page.Click(".confirm-button");

        Assert.Equal(["192.0.2.5:40004 Disconnected by the administrator."], _disconnected);
        Assert.Equal(keep.Id, Assert.Single(Registry.GetAll()).Id);
        Assert.Single(page.FindAll(".connection-row"));
        Assert.Contains(Toasts.Messages, m => m.Text.Contains("dave"));
    }
}
