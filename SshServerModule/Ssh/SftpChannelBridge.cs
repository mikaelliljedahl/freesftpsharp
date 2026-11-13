using FxSsh.Services;
using Microsoft.Extensions.Logging;
using SshServerModule.Services;
using System;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace FxSsh.SshServerModule
{
    /// <summary>
    /// Connects a <see cref="SftpSubsystem"/> to an FxSsh session channel.
    /// <para>
    /// Requests are handled on the FxSsh receive loop. The responses go to a queue, and one task sends them in
    /// order with <see cref="Channel.SendDataAsync"/>. The receive loop must not wait for the client's window
    /// (the window adjust message comes on the same loop), and the responses must stay in order.
    /// </para>
    /// <para>
    /// When the client sends EOF or CLOSE, or the session ends, the bridge sends the queued responses, then EOF, exit-status 0 and
    /// CLOSE (RFC 4254 sections 5.3 and 6.10), and disposes the subsystem.
    /// </para>
    /// </summary>
    internal static class SftpChannelBridge
    {
        internal static void Attach(Session session, SessionChannel channel, SftpSubsystem sftp, ILogger logger)
        {
            var outbound = System.Threading.Channels.Channel.CreateUnbounded<byte[]>(
                new UnboundedChannelOptions { SingleReader = true });

            // The data is a view over the FxSsh receive buffer; OnInput copies what it keeps.
            channel.DataReceived += (_, data) =>
            {
                try
                {
                    sftp.OnInput(data);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "SFTP request on channel {ChannelId} failed.", channel.ServerChannelId);
                }
            };
            sftp.OnOutput += (_, packet) => outbound.Writer.TryWrite(packet.ToArray());
            channel.EofReceived += (_, _) => outbound.Writer.TryComplete();
            channel.CloseReceived += (_, _) => outbound.Writer.TryComplete();
            // A lost connection gives no EOF or CLOSE; stop the pump so that the open files are closed.
            EventHandler<EventArgs> disconnected = (_, _) => outbound.Writer.TryComplete();
            session.Disconnected += disconnected;

            _ = PumpAsync(channel, sftp, outbound.Reader, logger, () => session.Disconnected -= disconnected);
        }

        private static async Task PumpAsync(SessionChannel channel, SftpSubsystem sftp, ChannelReader<byte[]> outbound, ILogger logger, Action detach)
        {
            try
            {
                await foreach (var packet in outbound.ReadAllAsync())
                    await channel.SendDataAsync(packet);

                channel.SendEof();
                channel.SendClose(0);
            }
            catch (Exception ex) when (ex is ObjectDisposedException or SshConnectionException or InvalidOperationException)
            {
                // The session or the channel was closed while responses were waiting.
                logger.LogDebug(ex, "SFTP channel {ChannelId} closed before all responses were sent.", channel.ServerChannelId);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Sending SFTP responses on channel {ChannelId} failed.", channel.ServerChannelId);
            }
            finally
            {
                detach();
                sftp.Dispose();
            }
        }
    }
}
