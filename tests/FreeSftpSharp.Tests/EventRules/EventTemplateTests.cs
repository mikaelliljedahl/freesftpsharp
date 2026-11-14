using SshServer.EventRules;
using SshServer.Interfaces;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;

namespace FreeSftpSharp.Tests.EventRules;

public sealed class EventTemplateTests
{
    private static readonly IReadOnlyDictionary<string, string> Values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["Name"] = "a b&c.txt",
        ["Username"] = "Alice",
    };

    [Theory]
    [InlineData("/processed/{{Name}}", "/processed/a b&c.txt")]
    [InlineData("/processed/{{ name }}", "/processed/a b&c.txt")]
    [InlineData("https://erp/?f={{Name | urlencode}}", "https://erp/?f=a%20b%26c.txt")]
    [InlineData("{{Username|lower}}-{{Username | upper}}", "alice-ALICE")]
    [InlineData("{{Unknown}}x", "x")]
    [InlineData("no placeholder", "no placeholder")]
    public void Placeholders_are_replaced(string template, string expected)
        => Assert.Equal(expected, EventTemplate.Render(template, Values));

    [Theory]
    [InlineData("{{Name | base64}}", "filter")]
    [InlineData("{{Name", "not valid")]
    public void A_template_with_an_unknown_filter_or_an_open_placeholder_is_refused(string template, string error)
        => Assert.Contains(error, Assert.Single(EventTemplate.Validate(template)));

    [Fact]
    public void The_values_of_a_file_event()
    {
        var rule = new EventRule { Name = "move" };
        var e = new FileEvent(FileEventType.Upload)
        {
            Timestamp = new DateTimeOffset(2026, 11, 1, 12, 0, 0, TimeSpan.Zero),
            Username = "alice",
            VirtualPath = "/incoming/report.csv",
            FileSize = 42,
            Protocol = "SFTP",
            RemoteIp = "192.0.2.10",
        };

        var values = EventPlaceholders.For(rule, e, EventNames.Of(e), null, e.Timestamp, new Dictionary<string, string> { ["RetentionDeleted"] = "3" });

        Assert.Equal("move", values["Rule"]);
        Assert.Equal("File.Upload", values["Event"]);
        Assert.Equal("alice", values["Username"]);
        Assert.Equal("report.csv", values["Name"]);
        Assert.Equal("/incoming", values["Dir"]);
        Assert.Equal("42", values["FileSize"]);
        Assert.Equal("Ok", values["Status"]);
        Assert.Equal("192.0.2.10", values["Ip"]);
        Assert.Equal("2026-11-01", values["Date"]);
        Assert.Equal("2026-11-01T12:00:00.0000000Z", values["Timestamp"]);
        Assert.Equal("3", values["RetentionDeleted"]);
    }

    [Fact]
    public void The_values_of_a_provider_event_have_the_object_without_secrets()
    {
        var user = new User { Username = "bob", UserRootDirectory = "/data/bob", HashedPassword = "secret-hash" };
        var e = new ProviderEvent(ProviderAction.Add, ProviderObjectType.User, "bob") { Object = UserSnapshot.From(user) };

        var values = EventPlaceholders.For(new EventRule { Name = "r" }, e, EventNames.Of(e), null, DateTimeOffset.UtcNow, new Dictionary<string, string>());

        Assert.Equal("User", values["ObjectType"]);
        Assert.Equal("bob", values["ObjectName"]);
        Assert.Contains("/data/bob", values["ObjectData"]);
        Assert.DoesNotContain("secret-hash", values["ObjectData"]);
    }
}
