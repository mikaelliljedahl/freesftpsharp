using System.Net;
using FreeSftpSharp.Ftp;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;
using FreeSftpSharp.Tests.Infrastructure;

namespace FreeSftpSharp.Tests.Ftp;

/// <summary>The command parser, the reply format, the listings, the address parsers and the options (issue #72).</summary>
public sealed class FtpProtocolTests
{
    [Theory]
    [InlineData("USER alice", "USER", "alice")]
    [InlineData("user alice", "USER", "alice")]
    [InlineData("STOR my file.txt", "STOR", "my file.txt")]
    [InlineData("STOR  leading space", "STOR", " leading space")]
    [InlineData("PWD", "PWD", "")]
    [InlineData("CWD ", "CWD", "")]
    public void The_parser_keeps_the_argument_as_sent(string line, string verb, string argument)
    {
        var command = FtpCommand.Parse(line);
        Assert.NotNull(command);
        Assert.Equal(verb, command.Value.Verb);
        Assert.Equal(argument, command.Value.Argument);
    }

    [Theory]
    [InlineData("")]
    [InlineData("AB")]
    [InlineData("TOOLONG x")]
    [InlineData("US3R x")]
    [InlineData(" USER x")]
    public void The_parser_refuses_a_line_without_a_valid_verb(string line) => Assert.Null(FtpCommand.Parse(line));

    [Fact]
    public void The_password_is_never_in_the_text_of_a_command() =>
        Assert.Equal("PASS ****", FtpCommand.Parse("PASS secret")!.Value.ToString());

    [Fact]
    public void A_reply_is_one_line_or_a_multi_line_reply_with_indented_middle_lines()
    {
        Assert.Equal("200 OK.\r\n", FtpReply.Format(200, "OK."));
        Assert.Equal("211-Features:\r\n EPSV\r\n UTF8\r\n211 End\r\n", FtpReply.Format(211, "Features:\nEPSV\nUTF8\nEnd"));
        // A line end in a value (for example a file name) cannot end the reply early.
        Assert.Equal("250-a\r\n 226 fake\r\n250 b\r\n", FtpReply.Format(250, "a\r\n226 fake\nb"));
    }

    [Fact]
    public void A_quote_in_a_path_is_doubled() => Assert.Equal("\"/a\"\"b\"", FtpReply.QuotePath("/a\"b"));

    [Fact]
    public void Telnet_commands_are_removed_from_a_line()
    {
        // IAC IP IAC DM before ABOR (RFC 959 section 4.1.3), IAC DO option, and IAC IAC as a literal 0xFF.
        Assert.Equal("ABOR"u8.ToArray(), FtpControlChannel.RemoveTelnet([0xFF, 0xF4, 0xFF, 0xF2, .. "ABOR"u8.ToArray()]));
        Assert.Equal("AB"u8.ToArray(), FtpControlChannel.RemoveTelnet([(byte)'A', 0xFF, 0xFD, 0x01, (byte)'B']));
        Assert.Equal(new byte[] { (byte)'A', 0xFF }, FtpControlChannel.RemoveTelnet([(byte)'A', 0xFF, 0xFF]));
    }

    [Fact]
    public void List_lines_have_the_ls_format()
    {
        var now = new DateTime(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);
        var file = new FileSystemEntry("report.txt", FileSystemEntryType.File, 1234, new DateTime(2026, 11, 4, 9, 5, 0, DateTimeKind.Utc), now)
            { Permissions = 0x1A4 };
        var dir = new FileSystemEntry("old", FileSystemEntryType.Directory, 0, new DateTime(2020, 1, 2, 0, 0, 0, DateTimeKind.Utc), now);

        Assert.Equal("-rw-r--r-- 1 ftp ftp         1234 Nov  4 09:05 report.txt", FtpListing.ListLine(file, now));
        Assert.Equal("drwxr-xr-x 1 ftp ftp            0 Jan  2  2020 old", FtpListing.ListLine(dir, now));
        Assert.Equal("type=file;size=1234;modify=20261104090500; report.txt", FtpListing.Facts(file, "report.txt"));
        Assert.Equal("type=dir;modify=20200102000000; old", FtpListing.Facts(dir, "old"));
    }

    [Theory]
    [InlineData("-la", "")]
    [InlineData("-a /dir", "/dir")]
    [InlineData("-l -a  sub dir", "sub dir")]
    [InlineData("name", "name")]
    public void The_ls_options_of_LIST_are_ignored(string argument, string path) => Assert.Equal(path, FtpListing.WithoutOptions(argument));

    [Fact]
    public void Port_and_eprt_addresses_are_parsed()
    {
        Assert.Equal(new IPEndPoint(IPAddress.Parse("132.235.1.2"), 6275), FtpAddresses.ParsePort("132,235,1,2,24,131"));
        Assert.Equal(new IPEndPoint(IPAddress.Parse("132.235.1.2"), 6275), FtpAddresses.ParseEprt("|1|132.235.1.2|6275|"));
        Assert.Equal(new IPEndPoint(IPAddress.Parse("1080::8:800:200C:417A"), 5282), FtpAddresses.ParseEprt("|2|1080::8:800:200C:417A|5282|"));
        Assert.Null(FtpAddresses.ParsePort("132,235,1,2,24"));
        Assert.Null(FtpAddresses.ParsePort("132,235,1,256,24,131"));
        Assert.Null(FtpAddresses.ParseEprt("|2|132.235.1.2|6275|"));
        Assert.Null(FtpAddresses.ParseEprt("|1|132.235.1.2|0|"));
        Assert.Equal("Entering Passive Mode (127,0,0,1,195,80).", FtpAddresses.PasvReply(IPAddress.Loopback, 50000));
    }

    [Fact]
    public void Storage_errors_have_ftp_reply_codes()
    {
        Assert.Equal(550, FtpErrors.Of(new FileSystemException(FileSystemError.PermissionDenied, "x")).Code);
        Assert.Equal(550, FtpErrors.Of(new FileSystemException(FileSystemError.NoSuchFile, "x")).Code);
        Assert.Equal(552, FtpErrors.Of(new FileSystemException(FileSystemError.QuotaExceeded, "x")).Code);
        Assert.Equal(553, FtpErrors.Of(new FileSystemException(FileSystemError.InvalidPath, "x")).Code);
        Assert.Equal(451, FtpErrors.Of(new FileSystemException(FileSystemError.Failure, "x")).Code);
        var hook = FtpErrors.Of(new FileSystemException(FileSystemError.PermissionDenied, "x") { ClientMessage = "No uploads\ntoday." });
        Assert.Equal("Permission denied. No uploads today.", hook.Text);
    }

    [Theory]
    [InlineData("PassivePortRange", "50000")]
    [InlineData("PassivePortRange", "100-200")]
    [InlineData("PassivePortRange", "60000-50000")]
    [InlineData("PassiveExternalAddress", "::1")]
    [InlineData("PassiveExternalAddress", "nat.example.com")]
    [InlineData("Banner", "two\nlines")]
    [InlineData("IdleTimeoutSeconds", "0")]
    [InlineData("Port", "70000")]
    public void Invalid_options_of_an_enabled_server_are_refused(string property, string value)
    {
        var options = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Enabled"] = "true", [property] = value })
            .Build().Get<FtpOptions>()!;
        Assert.True(new FtpOptionsValidator().Validate(null, options).Failed);
    }

    [Fact]
    public void The_defaults_are_valid_and_safe()
    {
        var options = new FtpOptions { Enabled = true };
        Assert.True(new FtpOptionsValidator().Validate(null, options).Succeeded);
        Assert.Equal(FtpTlsMode.Required, options.Tls.Mode);
        Assert.False(options.AllowActiveMode);
        Assert.Equal((50000, 50100), options.PassivePorts);
    }

    [Fact]
    public async Task Without_configuration_the_ftp_server_opens_no_port()
    {
        var services = new ServiceCollection().AddLogging()
            .AddSingleton<ISettingsRepository>(new InMemorySettingsRepository(new ServerSettings()))
            .AddSingleton<IFileSystemFactory>(new ThrowingFactory())
            .AddFtp(new ConfigurationBuilder().Build());
        await using var provider = services.BuildServiceProvider();
        var hosted = provider.GetServices<IHostedService>().OfType<FtpServer>().Single();
        await hosted.StartAsync(TestContext.Current.CancellationToken);
        Assert.False(hosted.IsListening);
        Assert.Empty(hosted.LocalEndPoints);
        await hosted.StopAsync(TestContext.Current.CancellationToken);
    }

    private sealed class ThrowingFactory : IFileSystemFactory
    {
        public ValueTask<IFileSystem> CreateAsync(User user, ClientContext client, CancellationToken ct) => throw new InvalidOperationException();
    }
}
