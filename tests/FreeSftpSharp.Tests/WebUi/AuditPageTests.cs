using Bunit;
using SshServer.Interfaces.Audit;
using AuditPage = FxSshSftpServer.Components.Pages.Audit;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>The Audit page: the entries newest first, the filters and the CSV export.</summary>
public sealed class AuditPageTests : AdminUiComponentContext
{
    private static readonly DateTime Today = new(2026, 11, 14, 9, 0, 0, DateTimeKind.Utc);

    private void Add(string type, string username, DateTime at, string status = "Ok", string category = "File")
        => AuditLog.AppendAsync(new AuditEntry
        {
            TimestampUtc = at, Category = category, Type = type, Status = status, Username = username, Path = "/" + type + ".txt",
            RemoteIp = "192.0.2.9", Size = 2048,
        }, CancellationToken.None).GetAwaiter().GetResult();

    [Fact]
    public void The_entries_are_listed_newest_first()
    {
        Add("Upload", "alice", Today.AddHours(-1));
        Add("Delete", "bob", Today);

        var page = Render<AuditPage>();

        page.WaitForAssertion(() => Assert.Equal("2", page.Find("#audit-count").TextContent));
        var rows = page.FindAll("#audit-table tbody tr");
        Assert.Contains("Delete", rows[0].TextContent);
        Assert.Contains("bob", rows[0].TextContent);
        Assert.Contains("2.0 KiB", rows[1].TextContent);
    }

    [Fact]
    public void The_filter_by_user_status_and_date_narrows_the_list()
    {
        Add("Upload", "alice", Today.AddDays(-2));
        Add("Upload", "alice", Today, "Error");
        Add("LoginFailed", "alice", Today, "Failed", "Auth");
        Add("Upload", "bob", Today);
        var page = Render<AuditPage>();
        page.WaitForAssertion(() => Assert.Equal("4", page.Find("#audit-count").TextContent));

        page.Change("#filter-user", "ALICE");
        page.Change("#filter-from", DateOnly.FromDateTime(Today).ToString("yyyy-MM-dd"));
        page.Change("#filter-type", "Upload");
        page.Submit("#audit-filter");

        page.WaitForAssertion(() => Assert.Equal("1", page.Find("#audit-count").TextContent));
        Assert.Contains("Error", page.Find("#audit-table tbody tr").TextContent);

        page.Change("#filter-status", "Ok");
        page.Submit("#audit-filter");
        page.WaitForAssertion(() => Assert.NotNull(page.Find("#no-audit-entries")));
    }

    [Fact]
    public void Export_saves_a_csv_file_with_the_filtered_entries()
    {
        Add("Upload", "alice", Today);
        Add("Upload", "bob", Today);
        var save = JSInterop.SetupVoid("BlazorDownloadFile", _ => true);
        var page = Render<AuditPage>();
        page.Change("#filter-user", "bob");

        page.Click("#export-audit");

        var call = Assert.Single(save.Invocations);
        Assert.StartsWith("audit-", (string)call.Arguments[0]!);
        Assert.Equal("text/csv", call.Arguments[1]);
        var csv = System.Text.Encoding.UTF8.GetString((byte[])call.Arguments[2]!);
        Assert.Contains("bob", csv);
        Assert.DoesNotContain("alice", csv);
    }

    [Fact]
    public void Without_an_audit_table_the_page_says_so()
    {
        AuditLog.IsEnabled = false;

        var page = Render<AuditPage>();

        Assert.NotNull(page.Find("#audit-disabled"));
    }
}
