using FxSshSftpServer.Models;
using SshServer.Interfaces.Webhooks;

namespace FreeSftpSharp.Tests.Webhooks;

/// <summary>The form of the Webhooks page: header and user lines, a generated secret for a new webhook.</summary>
public sealed class WebhookFormTests
{
    [Fact]
    public void A_new_form_has_a_random_secret()
    {
        Assert.Matches("^[0-9a-f]{64}$", WebhookForm.New().NewSecret);
        Assert.NotEqual(WebhookForm.New().NewSecret, WebhookForm.New().NewSecret);
    }

    [Fact]
    public void Header_and_user_lines_become_the_input_and_a_bad_header_line_is_an_error()
    {
        var form = new WebhookForm
        {
            Name = "hook", Url = "https://x.example", Headers = "Authorization: Bearer a:b\r\n\r\nX-Key:  1 ", Users = "alice, bob\ncarol",
        };
        form.EventTypes.Add("File.Upload");

        var (input, errors) = form.ToInput();

        Assert.Empty(errors);
        Assert.Equal("Bearer a:b", input.Headers["Authorization"]);
        Assert.Equal("1", input.Headers["X-Key"]);
        Assert.Equal(["alice", "bob", "carol"], input.Users);
        Assert.Equal(["File.Upload"], input.EventTypes);
        Assert.Null(input.NewSecret);

        form.Headers = "no colon here";
        Assert.Single(form.ToInput().Errors);
    }

    [Fact]
    public void An_edit_form_shows_whether_a_secret_is_set_but_not_the_secret()
    {
        var form = WebhookForm.From(new Webhook { Id = 3, Name = "hook", Url = "https://x.example", ProtectedSecret = "CfDJ8-encrypted", Sync = true, FailOpen = true });

        Assert.True(form.HasSecret);
        Assert.Equal("", form.NewSecret);
        Assert.True(form.ToInput().Input.FailOpen);
    }
}
