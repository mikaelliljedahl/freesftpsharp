using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// When the connection is lost without SSH_MSG_CHANNEL_CLOSE, the server must close the files that the
/// SFTP session has open (on Windows an open file cannot be removed or replaced).
/// </summary>
public sealed class SftpSessionTeardownTests : IClassFixture<SftpServerFixture>
{
    private readonly SftpServerFixture _server;

    public SftpSessionTeardownTests(SftpServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task Lost_connection_closes_the_open_files()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "The test finds the open files of the process in /proc/self/fd.");
        var path = _server.CreateUniqueDirectory("teardown") + "/open.bin";
        var physicalPath = Path.GetFullPath(_server.PhysicalPath(path));

        var proxy = new SlowDownstreamProxy(_server.Port, pauseMilliseconds: 0);
        var client = new SftpClient(SftpServerFixture.Host, proxy.Port, _server.Username, _server.Password);
        try
        {
            client.Connect();
            var stream = client.Create(path);
            stream.Write([1, 2, 3]);
            stream.Flush();
            Assert.True(await WaitUntilAsync(() => IsOpenByThisProcess(physicalPath)), "The server did not open the file.");

            await proxy.DisposeAsync(); // the TCP connection is lost; the client sends nothing more

            Assert.True(await WaitUntilAsync(() => !IsOpenByThisProcess(physicalPath)), "The server did not close the file after the connection was lost.");
        }
        finally
        {
            try { client.Dispose(); } catch { /* the connection is gone */ }
            await proxy.DisposeAsync();
        }
    }

    private static bool IsOpenByThisProcess(string physicalPath)
    {
        foreach (var fd in Directory.EnumerateFileSystemEntries("/proc/self/fd"))
        {
            try
            {
                if (new FileInfo(fd).LinkTarget == physicalPath)
                    return true;
            }
            catch (IOException)
            {
                // the descriptor was closed while we looked at it
            }
        }
        return false;
    }

    private static async Task<bool> WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 100; i++)
        {
            if (condition())
                return true;
            await Task.Delay(50);
        }
        return condition();
    }
}
