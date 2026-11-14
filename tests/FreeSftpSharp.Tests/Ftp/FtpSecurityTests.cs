using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using FreeSftpSharp.Tests.WebDav;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;

namespace FreeSftpSharp.Tests.Ftp;

/// <summary>The login, TLS and connection rules of the FTP server, on a raw control connection (issue #72).</summary>
public sealed partial class FtpSecurityTests
{
    private static async Task LoginAsync(FtpRawClient raw, string username, string password = FtpTestHost.Password)
    {
        Assert.Equal(331, (await raw.CommandAsync("USER " + username)).Code);
        Assert.Equal(230, (await raw.CommandAsync("PASS " + password)).Code);
    }

    [Fact]
    public async Task With_tls_required_USER_before_AUTH_TLS_gets_530_and_the_password_is_not_checked()
    {
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("alice");
        await using var raw = await host.RawAsync();
        Assert.Equal(220, (await raw.ReadAsync()).Code);

        Assert.Equal(530, (await raw.CommandAsync("USER alice")).Code);
        Assert.Equal(530, (await raw.CommandAsync("PASS " + FtpTestHost.Password)).Code);
        Assert.Equal(530, (await raw.CommandAsync("LIST")).Code);
        Assert.DoesNotContain(host.Events.Published.OfType<AuthEvent>(), e => e.Username == "alice");

        await raw.StartTlsAsync();
        await LoginAsync(raw, "alice");
        var login = Assert.Single(host.Events.Published.OfType<AuthEvent>(), e => e.Type == AuthEventType.LoginOk);
        Assert.Equal(ConnectionProtocols.Ftp, login.Protocol);
        Assert.Equal("password", login.Method);
    }

    [Fact]
    public async Task With_tls_required_the_data_connections_must_be_protected()
    {
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("alice");
        await using var raw = await host.RawAsync();
        await raw.ReadAsync();
        await raw.StartTlsAsync();
        await LoginAsync(raw, "alice");

        Assert.Equal(534, (await raw.CommandAsync("PROT C")).Code);
        Assert.Equal(229, (await raw.CommandAsync("EPSV")).Code);
        Assert.Equal(521, (await raw.CommandAsync("LIST")).Code);
        Assert.Equal(200, (await raw.CommandAsync("PBSZ 0")).Code);
        Assert.Equal(200, (await raw.CommandAsync("PROT P")).Code);
    }

    [Fact]
    public async Task Commands_sent_in_clear_text_after_AUTH_TLS_close_the_connection()
    {
        await using var host = await FtpTestHost.StartAsync();
        await using var raw = await host.RawAsync();
        await raw.ReadAsync();

        // The injected USER would run as if it came over TLS (STARTTLS command injection).
        await raw.SendBytesAsync(Encoding.ASCII.GetBytes("AUTH TLS\r\nUSER injected\r\n"));
        Assert.Equal(234, (await raw.ReadAsync()).Code);
        Assert.True(await raw.IsClosedAsync());
    }

    [Fact]
    public async Task With_tls_disabled_plain_ftp_works_and_AUTH_TLS_is_refused()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:Tls:Mode"] = "Disabled" });
        host.AddUser("alice");
        await using var raw = await host.RawAsync();
        await raw.ReadAsync();

        Assert.Equal(502, (await raw.CommandAsync("AUTH TLS")).Code);
        Assert.DoesNotContain("AUTH TLS", (await raw.CommandAsync("FEAT")).Text);
        await LoginAsync(raw, "alice");
        Assert.Equal(257, (await raw.CommandAsync("PWD")).Code);
    }

    [Fact]
    public async Task A_wrong_password_gets_530_and_the_connection_closes_after_three_failures()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:Tls:Mode"] = "Optional" });
        host.AddUser("alice");
        await using var raw = await host.RawAsync();
        await raw.ReadAsync();

        for (var i = 0; i < 2; i++)
        {
            Assert.Equal(331, (await raw.CommandAsync("USER alice")).Code);
            Assert.Equal(530, (await raw.CommandAsync("PASS wrong")).Code);
        }
        Assert.Equal(331, (await raw.CommandAsync("USER alice")).Code);
        Assert.Equal(421, (await raw.CommandAsync("PASS wrong")).Code);
        Assert.True(await raw.IsClosedAsync());
        Assert.Equal(3, host.Events.Published.OfType<AuthEvent>().Count(e => e is { Type: AuthEventType.LoginFailed, Protocol: ConnectionProtocols.Ftp }));
    }

    [Fact]
    public async Task A_user_without_the_ftp_flag_gets_530_after_the_password()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:Tls:Mode"] = "Optional" });
        host.AddUser("sftp-only", u => u.AllowedProtocols = UserProtocols.Sftp | UserProtocols.WebDav);
        await using var raw = await host.RawAsync();
        await raw.ReadAsync();

        Assert.Equal(331, (await raw.CommandAsync("USER sftp-only")).Code);
        var (code, text) = await raw.CommandAsync("PASS " + FtpTestHost.Password);
        Assert.Equal(530, code);
        Assert.Contains("not allowed", text);
    }

    [Fact]
    public async Task A_totp_user_logs_in_with_an_ftp_app_password_only()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:Tls:Mode"] = "Optional" });
        var (ftp, ftpSecret) = AppPasswordGenerator.Create("ftp", UserProtocols.Ftp, DateTime.UtcNow, null);
        var (webdav, webdavSecret) = AppPasswordGenerator.Create("dav", UserProtocols.WebDav, DateTime.UtcNow, null);
        var user = host.AddUser("totp", u => u.AppPasswords = [ftp, webdav]);
        host.TwoFactor.UserIds.Add(user.Id);

        await using (var raw = await host.RawAsync())
        {
            await raw.ReadAsync();
            Assert.Equal(331, (await raw.CommandAsync("USER totp")).Code);
            Assert.Equal(530, (await raw.CommandAsync("PASS " + FtpTestHost.Password)).Code);
            Assert.Equal(331, (await raw.CommandAsync("USER totp")).Code);
            Assert.Equal(530, (await raw.CommandAsync("PASS " + webdavSecret)).Code);
        }
        await using (var raw = await host.RawAsync())
        {
            await raw.ReadAsync();
            await LoginAsync(raw, "totp", ftpSecret);
        }
        Assert.Contains(host.Events.Published.OfType<AuthEvent>(), e => e is { Type: AuthEventType.LoginOk, Method: "app-password" });
    }

    [Fact]
    public async Task Commands_before_the_login_get_530()
    {
        await using var host = await FtpTestHost.StartAsync();
        await using var raw = await host.RawAsync();
        await raw.ReadAsync();

        foreach (var command in new[] { "PWD", "CWD /", "RETR a", "STOR a", "PASV", "DELE a", "MKD a" })
            Assert.Equal(530, (await raw.CommandAsync(command)).Code);
        Assert.Equal(211, (await raw.CommandAsync("FEAT")).Code);
        Assert.Equal(200, (await raw.CommandAsync("NOOP")).Code);
        Assert.Equal(500, (await raw.CommandAsync("X1")).Code);
        Assert.Equal(221, (await raw.CommandAsync("QUIT")).Code);
    }

    [Fact]
    public async Task A_command_line_over_the_limit_gets_500_and_closes_the_connection()
    {
        await using var host = await FtpTestHost.StartAsync();
        await using var raw = await host.RawAsync();
        await raw.ReadAsync();

        await raw.SendAsync("NOOP " + new string('a', 5000));
        Assert.Equal(500, (await raw.ReadAsync()).Code);
        Assert.True(await raw.IsClosedAsync());
    }

    [Fact]
    public async Task An_idle_connection_is_closed_with_421()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:IdleTimeoutSeconds"] = "1" });
        await using var raw = await host.RawAsync();
        await raw.ReadAsync();

        Assert.Equal(421, (await raw.ReadAsync()).Code);
        Assert.True(await raw.IsClosedAsync());
    }

    [Fact]
    public async Task The_connections_per_address_are_limited()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:MaxConnectionsPerIp"] = "2" });
        await using var first = await host.RawAsync();
        await using var second = await host.RawAsync();
        Assert.Equal(220, (await first.ReadAsync()).Code);
        Assert.Equal(220, (await second.ReadAsync()).Code);

        await using (var third = await host.RawAsync())
            Assert.Equal(421, (await third.ReadAsync()).Code);

        await first.CommandAsync("QUIT");
        await WaitUntilAsync(() => host.Connections.GetAll().Count == 1);
        // The listener frees the slot of the address just after the session left the registry: try again for a moment.
        var code = 0;
        for (var attempt = 0; attempt < 40 && code != 220; attempt++)
        {
            if (attempt > 0)
                await Task.Delay(25, TestContext.Current.CancellationToken);
            await using var fourth = await host.RawAsync();
            code = (await fourth.ReadAsync()).Code;
        }
        Assert.Equal(220, code);
    }

    [Fact]
    public async Task Active_mode_is_off_by_default()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:Tls:Mode"] = "Optional" });
        host.AddUser("alice");
        await using var raw = await host.RawAsync();
        await raw.ReadAsync();
        await LoginAsync(raw, "alice");

        Assert.Equal(502, (await raw.CommandAsync("PORT 127,0,0,1,195,80")).Code);
        Assert.Equal(502, (await raw.CommandAsync("EPRT |1|127.0.0.1|50000|")).Code);
        Assert.DoesNotContain("EPRT", (await raw.CommandAsync("FEAT")).Text);
    }

    [Fact]
    public async Task Active_mode_connects_only_to_the_client_and_a_high_port()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?>
            { ["Ftp:Tls:Mode"] = "Optional", ["Ftp:AllowActiveMode"] = "true" });
        host.AddUser("alice");
        await using var raw = await host.RawAsync();
        await raw.ReadAsync();
        await LoginAsync(raw, "alice");

        // FTP bounce (RFC 2577): another host, or a privileged port of the client.
        Assert.Equal(504, (await raw.CommandAsync("PORT 10,0,0,1,195,80")).Code);
        Assert.Equal(504, (await raw.CommandAsync("PORT 127,0,0,1,0,25")).Code);
        Assert.Equal(504, (await raw.CommandAsync("EPRT |1|192.0.2.1|50000|")).Code);
        Assert.Equal(501, (await raw.CommandAsync("PORT 127,0,0,1")).Code);
        Assert.Equal(200, (await raw.CommandAsync("PORT 127,0,0,1,195,80")).Code);
    }

    [Fact]
    public async Task A_passive_port_is_in_the_range_and_accepts_only_the_client_address()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:Tls:Mode"] = "Optional" });
        host.AddUser("alice");
        await host.StorageOf("alice").WriteAllAsync("/a.txt", "hello");
        await using var raw = await host.RawAsync();
        await raw.ReadAsync();
        await LoginAsync(raw, "alice");

        var (code, text) = await raw.CommandAsync("PASV");
        Assert.Equal(227, code);
        var match = PasvRegex().Match(text);
        Assert.True(match.Success, text);
        Assert.Equal("127,0,0,1", match.Groups[1].Value);
        var port = int.Parse(match.Groups[2].Value) * 256 + int.Parse(match.Groups[3].Value);
        Assert.InRange(port, host.PassivePorts.First, host.PassivePorts.Last);

        // A connection from another address (127.0.0.2 is loopback on Linux and Windows) is closed: no PASV theft.
        using var thief = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            thief.Bind(new IPEndPoint(IPAddress.Parse("127.0.0.2"), 0));
        }
        catch (SocketException)
        {
            Assert.Skip("127.0.0.2 is not a local address here.");
        }
        await thief.ConnectAsync(IPAddress.Loopback, port, TestContext.Current.CancellationToken);
        await Task.Delay(100, TestContext.Current.CancellationToken); // the thief is first in the queue of the listener
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, TestContext.Current.CancellationToken);

        await raw.SendAsync("RETR a.txt");
        Assert.Equal(150, (await raw.ReadAsync()).Code);
        using var reader = new StreamReader(client.GetStream());
        Assert.Equal("hello", await reader.ReadToEndAsync(TestContext.Current.CancellationToken));
        Assert.Equal(226, (await raw.ReadAsync()).Code);
        var buffer = new byte[16];
        Assert.Equal(0, await thief.ReceiveAsync(buffer, SocketFlags.None, TestContext.Current.CancellationToken));
        Assert.Contains(host.Logs.Messages, m => m.Contains("Refused a data connection from 127.0.0.2"));
    }

    [Fact]
    public async Task A_protected_upload_is_complete_when_the_client_closes_without_reading_from_the_data_connection()
    {
        // lftp (GnuTLS) writes the file and closes the data socket without ever reading from it. Anything the server
        // sent after the handshake (TLS 1.3 session tickets) is then unread at the client, so its kernel answers with a
        // reset instead of a FIN, and the reset drops the data the server has not read yet: the file was truncated.
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("alice");
        await using var raw = await host.RawAsync();
        await raw.ReadAsync();
        await raw.StartTlsAsync();
        await LoginAsync(raw, "alice");
        Assert.Equal(200, (await raw.CommandAsync("PBSZ 0")).Code);
        Assert.Equal(200, (await raw.CommandAsync("PROT P")).Code);
        var data = new byte[2 * 1024 * 1024];
        new Random(3).NextBytes(data);

        for (var round = 0; round < 3; round++)
        {
            var (code, text) = await raw.CommandAsync("EPSV");
            Assert.Equal(229, code);
            var port = int.Parse(text.Split('|')[3], System.Globalization.CultureInfo.InvariantCulture);
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(IPAddress.Loopback, port, TestContext.Current.CancellationToken);
            await raw.SendAsync($"STOR /up{round}.bin");
            Assert.Equal(150, (await raw.ReadAsync()).Code);
            var ssl = new System.Net.Security.SslStream(new NetworkStream(socket, ownsSocket: false), false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync("localhost");
            await ssl.WriteAsync(data, TestContext.Current.CancellationToken);
            await ssl.FlushAsync(TestContext.Current.CancellationToken);
            socket.Close(); // no TLS close_notify and no read, like lftp

            Assert.Equal(226, (await raw.ReadAsync()).Code);
            Assert.Equal(data, await host.StorageOf("alice").ReadAllAsync($"/up{round}.bin"));
        }
    }

    [Fact]
    public async Task An_administrator_disconnect_closes_the_connection_with_421()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:Tls:Mode"] = "Optional" });
        host.AddUser("alice");
        await using var raw = await host.RawAsync();
        await raw.ReadAsync();
        await LoginAsync(raw, "alice");

        var connection = Assert.Single(host.Connections.GetAll());
        Assert.Equal(ConnectionProtocols.Ftp, connection.Protocol);
        Assert.Equal("alice", connection.Username);
        Assert.True(await host.Connections.DisconnectAsync(connection.Id, "maintenance"));

        var (code, text) = await raw.ReadAsync();
        Assert.Equal(421, code);
        Assert.Contains("maintenance", text);
        await WaitUntilAsync(() => host.Connections.GetAll().Count == 0);
        Assert.Contains(host.Events.Published.OfType<AuthEvent>(), e => e is { Type: AuthEventType.Logout, Protocol: ConnectionProtocols.Ftp });
    }

    [Fact]
    public async Task A_session_limit_of_the_user_is_kept()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:Tls:Mode"] = "Optional" });
        host.AddUser("alice", u => u.MaxSessions = 1);
        await using var first = await host.RawAsync();
        await first.ReadAsync();
        await LoginAsync(first, "alice");

        await using var second = await host.RawAsync();
        await second.ReadAsync();
        Assert.Equal(331, (await second.CommandAsync("USER alice")).Code);
        Assert.Equal(530, (await second.CommandAsync("PASS " + FtpTestHost.Password)).Code);
    }

    [Fact]
    public async Task Control_characters_of_a_client_do_not_forge_log_lines()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:Tls:Mode"] = "Optional" });
        await using var raw = await host.RawAsync();
        await raw.ReadAsync();

        await raw.CommandAsync("USER evil\u001b[31m\rFAKE");
        await raw.CommandAsync("PASS x");
        Assert.DoesNotContain(host.Logs.Messages, m => m.Contains('\u001b') || m.Contains('\r'));
        Assert.Contains(host.Logs.Messages, m => m.Contains("evil\\u001b[31m\\rFAKE"));
    }

    internal static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 200 && !condition(); i++)
            await Task.Delay(25);
        Assert.True(condition());
    }

    [GeneratedRegex(@"\((\d+,\d+,\d+,\d+),(\d+),(\d+)\)")]
    private static partial Regex PasvRegex();
}
