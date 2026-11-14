using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Ftp;

/// <summary>The shared services that every <see cref="FtpSession"/> uses.</summary>
internal sealed class FtpServices
{
    public FtpServices(IOptions<FtpOptions> options, PasswordLoginService login, ISettingsRepository repository, IFileSystemFactory fileSystems,
        IConnectionRegistry connections, FtpPassivePorts passivePorts, FtpCertificate certificate, ILoggerFactory loggers, IEventBus? events = null)
    {
        Options = options.Value;
        Login = login;
        Repository = repository;
        FileSystems = fileSystems;
        Connections = connections;
        PassivePorts = passivePorts;
        Certificate = certificate;
        Loggers = loggers;
        Events = events;
    }

    public FtpOptions Options { get; }
    public PasswordLoginService Login { get; }
    public ISettingsRepository Repository { get; }
    public IFileSystemFactory FileSystems { get; }
    public IConnectionRegistry Connections { get; }
    public FtpPassivePorts PassivePorts { get; }
    public FtpCertificate Certificate { get; }
    public ILoggerFactory Loggers { get; }
    public IEventBus? Events { get; }

    /// <summary>The clock of the auto-ban, the events and the listings.</summary>
    public TimeProvider Time => Login.Time;

    public async ValueTask PublishAsync(IEvent @event, ILogger logger)
    {
        if (Events == null)
            return;
        try
        {
            await Events.PublishAsync(@event, CancellationToken.None);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Could not publish the {Category} event {Type}.", @event.Category, @event.TypeName);
        }
    }
}
