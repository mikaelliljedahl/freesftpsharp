using System.Text.Json;
using SshServer.Interfaces;
using SshServer.Interfaces.Events;
using SshServer.Webhooks;

namespace FreeSftpSharp.Tests.Webhooks;

/// <summary>The JSON body: snake_case, SFTPGo names and values where they overlap, an event id and the attempt, no secrets.</summary>
public sealed class WebhookPayloadTests
{
    private static readonly DateTimeOffset At = new(2026, 11, 14, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void A_file_event_has_the_SFTPGo_fields()
    {
        var id = Guid.NewGuid();
        var e = new FileEvent(FileEventType.PreUpload)
        {
            Timestamp = At, Username = "alice", VirtualPath = "/in/a.csv", FileSize = 42, Elapsed = TimeSpan.FromMilliseconds(250),
            Status = FileEventStatus.QuotaExceeded, Protocol = "SFTP", RemoteIp = "192.0.2.1", SessionId = "s-1", Provider = "local",
        };

        var json = JsonDocument.Parse(WebhookPayload.WithAttempt(WebhookPayload.Create(e, id), 3)).RootElement;

        Assert.Equal(id.ToString(), json.GetProperty("event_id").GetString());
        Assert.Equal(3, json.GetProperty("attempt").GetInt32());
        Assert.Equal("File.PreUpload", json.GetProperty("event").GetString());
        Assert.Equal("pre-upload", json.GetProperty("action").GetString());
        Assert.Equal("alice", json.GetProperty("username").GetString());
        Assert.Equal("/in/a.csv", json.GetProperty("path").GetString());
        Assert.Equal("/in/a.csv", json.GetProperty("virtual_path").GetString());
        Assert.Equal(42, json.GetProperty("file_size").GetInt64());
        Assert.Equal(250, json.GetProperty("elapsed").GetInt64());
        Assert.Equal(3, json.GetProperty("status").GetInt32());
        Assert.Equal("SFTP", json.GetProperty("protocol").GetString());
        Assert.Equal("192.0.2.1", json.GetProperty("ip").GetString());
        Assert.Equal((At - DateTimeOffset.UnixEpoch).Ticks * 100, json.GetProperty("timestamp").GetInt64());
    }

    [Theory]
    [InlineData(FileEventType.FirstUpload, "first-upload")]
    [InlineData(FileEventType.SshCommand, "ssh_cmd")]
    [InlineData(FileEventType.Mkdir, "mkdir")]
    [InlineData(FileEventType.PreDelete, "pre-delete")]
    public void The_action_names_are_those_of_SFTPGo(FileEventType type, string action)
    {
        Assert.Equal(action, WebhookPayload.Action(new FileEvent(type)));
    }

    [Fact]
    public void A_user_change_has_the_snapshot_without_the_password_hash_or_key()
    {
        var user = new User { Username = "bob", HashedPassword = "PBKDF2-HASH-VALUE", RsaPublicKey = "ssh-rsa KEY", UserRootDirectory = "/srv/bob" };
        var e = new ProviderEvent(ProviderAction.Update, ProviderObjectType.User, "bob")
        {
            Timestamp = At, Object = UserSnapshot.From(user), ChangedFields = ["HashedPassword"],
        };

        var body = WebhookPayload.Create(e, Guid.NewGuid());
        var json = JsonDocument.Parse(body).RootElement;

        Assert.Equal("update", json.GetProperty("action").GetString());
        Assert.Equal("user", json.GetProperty("object_type").GetString());
        Assert.True(json.GetProperty("object").GetProperty("has_password").GetBoolean());
        Assert.DoesNotContain("PBKDF2-HASH-VALUE", body);
        Assert.DoesNotContain("ssh-rsa", body);
    }

    [Fact]
    public void An_auth_event_has_the_user_address_and_method()
    {
        var e = new AuthEvent(AuthEventType.LoginFailed) { Timestamp = At, Username = "eve", RemoteIp = "203.0.113.9", Protocol = "SSH", Method = "password", Reason = "wrong password" };

        var json = JsonDocument.Parse(WebhookPayload.Create(e, Guid.NewGuid())).RootElement;

        Assert.Equal(("Auth.LoginFailed", "login-failed", "eve", "203.0.113.9", "password"),
            (json.GetProperty("event").GetString(), json.GetProperty("action").GetString(), json.GetProperty("username").GetString(),
             json.GetProperty("ip").GetString(), json.GetProperty("login_method").GetString()));
    }

    [Theory]
    [InlineData("{\"message\":\"virus found in a.csv\"}", "virus found in a.csv")]
    [InlineData("plain text\r\nsecond line", "plain text  second line")]
    [InlineData("{\"error\":\"x\"}", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void The_client_message_of_a_403_is_the_json_message_or_the_text(string? body, string? expected)
    {
        Assert.Equal(expected, WebhookEventHook.ClientMessage(body));
    }

    [Fact]
    public void The_client_message_is_at_most_200_characters()
    {
        Assert.Equal(200, WebhookEventHook.ClientMessage(new string('x', 5000))!.Length);
    }
}
