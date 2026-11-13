using FxSsh.SshServerModule;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>
/// <see cref="SessionTimeouts"/>: ServerSettings.IdleTimeout (seconds, 0 = no timeout) gives either an
/// inactivity timeout or keepalive probes.
/// </summary>
public sealed class SessionTimeoutsTests
{
    [Fact]
    public void A_positive_idle_timeout_is_the_inactivity_timeout_without_keepalive()
    {
        var timeouts = SessionTimeouts.FromSettings(new ServerSettings { IdleTimeout = 600 });

        Assert.Equal(TimeSpan.FromSeconds(600), timeouts.InactivityTimeout);
        Assert.Null(timeouts.KeepaliveInterval); // keepalive traffic would keep an idle session open
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void No_idle_timeout_gives_keepalive_probes(int idleTimeout)
    {
        var timeouts = SessionTimeouts.FromSettings(new ServerSettings { IdleTimeout = idleTimeout });

        Assert.Null(timeouts.InactivityTimeout);
        Assert.Equal(HostedServer.KeepaliveInterval, timeouts.KeepaliveInterval);
    }
}
