using System.Net;
using System.Net.Sockets;
using System.Text;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings.Providers;
using FxSsh.SshServerModule;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Settings.PostgreSql;
using SshServer.Settings.Sql;
using SshServer.Settings.SqlServer;
using SshServerModule.Cluster;
using SshServerModule.Connections;
using SshServerModule.Events;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Cluster;

/// <summary>
/// One server node in-process (#75): the registrations of ServerConsoleApp on a <see cref="TestDatabase"/>, with
/// <c>Cluster:Enabled</c>, its own node id, its own SSH port and a poll interval of one second.
/// </summary>
internal sealed class TestNode : IAsyncDisposable
{
    private readonly IHost _host;

    private TestNode(IHost host, string nodeId, int port)
    {
        _host = host;
        NodeId = nodeId;
        Port = port;
    }

    public string NodeId { get; }

    public int Port { get; }

    public IServiceProvider Services => _host.Services;

    public ISettingsRepository Repository => Services.GetRequiredService<ISettingsRepository>();

    public IClusterConnections Connections => Services.GetRequiredService<IClusterConnections>();

    public IConnectionRegistry LocalConnections => Services.GetRequiredService<IConnectionRegistry>();

    public IIpBanService Bans => Services.GetRequiredService<IIpBanService>();

    /// <summary>Puts a host key in a new database, so that the nodes do not make a 4096-bit key.</summary>
    public static void PrepareDatabase(TestDatabase database)
    {
        using var repository = new SqlSettingsRepository(database.Options, createHostKey: () => TestCredentials.HostKey);
    }

    public static async Task<TestNode> StartAsync(TestDatabase database, string nodeId, string directory)
    {
        var port = FreePort();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(database.Configuration)
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Settings:LiteDbPath"] = Path.Combine(directory, "none.db"),
                ["SshServer:Port"] = port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["SshServer:BindToAddress"] = "127.0.0.1",
                ["Cluster:Enabled"] = "true",
                ["Cluster:NodeId"] = nodeId,
                ["Cluster:PollIntervalSeconds"] = "1",
            })
            .Build();

        var host = new HostBuilder()
            .ConfigureAppConfiguration(c => c.AddConfiguration(configuration))
            .ConfigureServices((context, services) =>
            {
                services.AddLogging();
                services.AddSshServerSettings(context.Configuration);
                services.AddPostgreSqlSettings();
                services.AddSqlServerSettings();
                services.AddSshServerEvents();
                services.AddSshServerStorage();
                services.AddLocalDiskStorage();
                services.AddHostedService<HostedServer>();
                services.AddSshServerSecurity();
                services.AddSshServerConnections();
                services.AddSshServerListenOptions();
                services.AddSshServerCluster(context.Configuration);
            })
            .Build();
        await host.StartAsync(TestContext.Current.CancellationToken);
        return new TestNode(host, nodeId, port);
    }

    /// <summary>True when the node closes a new connection before it sends its SSH identification (a refused address).</summary>
    public async Task<bool> RefusesConnectionsAsync()
    {
        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await tcp.ConnectAsync(IPAddress.Loopback, Port, timeout.Token);
        var buffer = new byte[64];
        try
        {
            var read = await tcp.GetStream().ReadAsync(buffer, timeout.Token);
            return read == 0 || !Encoding.ASCII.GetString(buffer, 0, read).StartsWith("SSH-", StringComparison.Ordinal);
        }
        catch (IOException)
        {
            return true;
        }
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _host.StopAsync(CancellationToken.None);
        _host.Dispose();
    }
}
