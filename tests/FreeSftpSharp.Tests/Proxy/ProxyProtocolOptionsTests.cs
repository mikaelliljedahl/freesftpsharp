using Microsoft.Extensions.Configuration;
using SshServerModule.Proxy;

namespace FreeSftpSharp.Tests.Proxy;

/// <summary>The <c>Proxy</c> section (#75): off by default, the allowed sources as a list or a comma separated text.</summary>
public sealed class ProxyProtocolOptionsTests
{
    private static IConfiguration Config(params (string Key, string Value)[] values) => new ConfigurationBuilder()
        .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
        .Build();

    [Fact]
    public void Without_configuration_the_PROXY_protocol_is_off()
    {
        Assert.False(ProxyProtocolOptions.FromConfiguration(Config()).Enabled);
    }

    [Fact]
    public void The_allowed_sources_are_a_comma_separated_text_or_a_list()
    {
        var text = ProxyProtocolOptions.FromConfiguration(Config(("Proxy:AllowedSources", "10.0.0.5, 192.168.0.0/16")));
        var list = ProxyProtocolOptions.FromConfiguration(Config(("Proxy:AllowedSources:0", "10.0.0.5"), ("Proxy:AllowedSources:1", "fd00::/8"),
            ("Proxy:HeaderTimeoutSeconds", "2")));

        Assert.True(text.Enabled);
        Assert.Equal(2, text.AllowedSources.Count);
        Assert.Equal(2, list.AllowedSources.Count);
        Assert.Equal(TimeSpan.FromSeconds(2), list.HeaderTimeout);
    }

    [Theory]
    [InlineData("Proxy:AllowedSources", "10.0.0.0/33")]
    [InlineData("Proxy:AllowedSources", "balancer.example.org")]
    [InlineData("Proxy:HeaderTimeoutSeconds", "0")]
    public void An_invalid_value_is_an_error_at_the_start(string key, string value)
    {
        var values = key == "Proxy:AllowedSources" ? new[] { (key, value) } : new[] { ("Proxy:AllowedSources", "10.0.0.1"), (key, value) };
        Assert.Throws<InvalidOperationException>(() => ProxyProtocolOptions.FromConfiguration(Config(values)));
    }
}
