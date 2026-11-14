using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet.Common;
using SshServer.Interfaces.Connections;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// The SSH server registers its sessions in the <see cref="IConnectionRegistry"/>: SSH.NET clients appear with their
/// user and address, leave it when they disconnect, can be disconnected by the server, and an open file shows the
/// growing byte count.
/// </summary>
public sealed class SshNetConnectionRegistryTests : IClassFixture<SftpServerFixture>
{
    private const string SecondUser = "second_person";
    private const string SecondPassword = "second-password";

    private readonly SftpServerFixture _server;

    public SshNetConnectionRegistryTests(SftpServerFixture server)
    {
        _server = server;
        if (_server.Repository.GetUser(SecondUser) == null)
            _server.AddUser(SecondUser, TestCredentials.HashPassword(SecondPassword));
    }

    private ConnectionInfo? Find(string username) =>
        _server.Connections.GetAll().SingleOrDefault(c => c.Username == username);

    [Fact]
    public async Task Two_clients_appear_with_their_users_and_addresses_and_leave_within_one_second()
    {
        using var first = _server.Connect();
        using var second = _server.CreateClient(SecondPassword, SecondUser);
        second.Connect();

        Assert.True(await WaitUntilAsync(() => Find(_server.Username) != null && Find(SecondUser) != null, TimeSpan.FromSeconds(5)));
        var one = Find(_server.Username)!;
        var two = Find(SecondUser)!;
        Assert.NotEqual(one.Id, two.Id);
        Assert.NotEqual(one.RemoteEndPoint, two.RemoteEndPoint);
        Assert.StartsWith(SftpServerFixture.Host + ":", one.RemoteEndPoint);
        Assert.StartsWith(SftpServerFixture.Host + ":", two.RemoteEndPoint);
        Assert.Equal(ConnectionProtocols.Sftp, one.Protocol);
        Assert.Equal("password", one.AuthMethod);
        Assert.NotNull(one.AuthenticatedAt);
        Assert.StartsWith("SSH-2.0-", one.ClientVersion);

        first.Disconnect();
        Assert.True(await WaitUntilAsync(() => _server.Connections.Get(one.Id) == null, TimeSpan.FromSeconds(1)),
            "The first client is still in the registry one second after it disconnected.");
        Assert.NotNull(_server.Connections.Get(two.Id));

        second.Disconnect();
        Assert.True(await WaitUntilAsync(() => _server.Connections.Get(two.Id) == null, TimeSpan.FromSeconds(1)),
            "The second client is still in the registry one second after it disconnected.");
    }

    [Fact]
    public async Task DisconnectAsync_closes_the_client_connection_and_removes_the_entry()
    {
        using var client = _server.CreateClient(SecondPassword, SecondUser);
        client.Connect();
        Assert.True(await WaitUntilAsync(() => Find(SecondUser) != null, TimeSpan.FromSeconds(5)));
        var id = Find(SecondUser)!.Id;
        // A client that keeps sending requests: the request in flight when the server disconnects fails.
        var busy = Task.Run(() =>
        {
            while (true)
            {
                try
                {
                    client.ListDirectory("/");
                }
                catch (Exception ex)
                {
                    return ex;
                }
            }
        }, TestContext.Current.CancellationToken);
        await Task.Delay(100, TestContext.Current.CancellationToken);

        Assert.True(await _server.Connections.DisconnectAsync(id, "Disconnected by the administrator."));

        Assert.Null(_server.Connections.Get(id));
        var error = await busy.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        // If the disconnect comes while a request is in flight, SSH.NET reports it with SshException ("Connection was closed
        // by the server."), the base class of SshConnectionException. If it comes between two requests, the next request
        // fails before it is sent, with InvalidOperationException (seen on the Ubuntu CI runner). Both are correct.
        Assert.True(error is SshException or InvalidOperationException, $"Unexpected exception: {error}");
        Assert.True(await WaitUntilAsync(() => !client.IsConnected, TimeSpan.FromSeconds(5)), "The client is still connected.");
        Assert.False(await _server.Connections.DisconnectAsync(id, "again"));
    }

    [Fact]
    public async Task An_upload_in_progress_shows_the_growing_byte_count()
    {
        var path = _server.CreateUniqueDirectory("registry") + "/upload.bin";
        using var client = _server.Connect();
        var id = (await WaitForAsync(() => Find(_server.Username)))!.Id;

        using (var stream = client.Create(path))
        {
            stream.Write(new byte[10_000]);
            stream.Flush();
            var first = await WaitForAsync(() => _server.Connections.Get(id)?.Transfers.SingleOrDefault(t => t.Bytes >= 10_000));
            Assert.Equal(path, first!.VirtualPath);
            Assert.Equal(TransferDirection.Upload, first.Direction);

            stream.Write(new byte[20_000]);
            stream.Flush();
            var second = await WaitForAsync(() => _server.Connections.Get(id)?.Transfers.SingleOrDefault(t => t.Bytes >= 30_000));
            Assert.Equal(first.Id, second!.Id);
            Assert.True(second.Bytes > first.Bytes);
        }

        Assert.True(await WaitUntilAsync(() => _server.Connections.Get(id)?.Transfers.Count == 0, TimeSpan.FromSeconds(5)),
            "The transfer did not end when the file was closed.");
    }

    private static async Task<T?> WaitForAsync<T>(Func<T?> value) where T : class
    {
        T? result = null;
        await WaitUntilAsync(() => (result = value()) != null, TimeSpan.FromSeconds(5));
        Assert.NotNull(result);
        return result;
    }

    private static async Task<bool> WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
                return true;
            await Task.Delay(20, TestContext.Current.CancellationToken);
        }
        return condition();
    }
}
