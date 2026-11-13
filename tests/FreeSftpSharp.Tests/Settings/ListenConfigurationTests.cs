using FxSsh.SshServerModule;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.Settings;

/// <summary>The <c>SshServer</c> configuration section: binding, switch mappings and precedence over the stored settings.</summary>
public sealed class ListenConfigurationTests
{
    private static ServerSettings Stored(int port = 22, params string[] bind) =>
        new() { ListenToPort = port, BindToAddress = bind.ToList() };

    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
            .Build();

    private static IConfiguration CommandLine(params string[] args) =>
        new ConfigurationBuilder().AddCommandLine(args, SshServerOptions.SwitchMappings).Build();

    private static SshServerOptions Bind(IConfiguration configuration) =>
        new ServiceCollection().AddSingleton(configuration).AddSshServerListenOptions()
            .BuildServiceProvider().GetRequiredService<IOptions<SshServerOptions>>().Value;

    [Fact]
    public void Options_are_bound_from_the_SshServer_section()
    {
        var options = Bind(Config(("SshServer:Port", "2222"), ("SshServer:BindToAddress:0", "127.0.0.1"), ("SshServer:BindToAddress:1", "::1")));

        Assert.Equal("2222", options.Port);
        Assert.Equal(new[] { "127.0.0.1", "::1" }, options.BindToAddress);
    }

    [Fact]
    public void BindToAddress_can_be_a_comma_separated_string()
    {
        var options = Bind(Config(("SshServer:BindToAddress", " 127.0.0.1 , ::1,,")));

        Assert.Equal(new[] { "127.0.0.1", "::1" }, options.BindToAddress);
    }

    [Fact]
    public void Environment_variable_names_use_a_double_underscore()
    {
        var variables = new Dictionary<string, string?> { ["SshServer__Port"] = "2022", ["SshServer__BindToAddress"] = "127.0.0.1" };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(variables.ToDictionary(v => v.Key.Replace("__", ":"), v => v.Value))
            .Build();

        var options = Bind(configuration);

        Assert.Equal("2022", options.Port);
        Assert.Equal(new[] { "127.0.0.1" }, options.BindToAddress);
    }

    [Fact]
    public void Switch_mappings_map_port_and_bind()
    {
        var options = Bind(CommandLine("--port", "22022", "--bind", "127.0.0.1,::1"));

        Assert.Equal("22022", options.Port);
        Assert.Equal(new[] { "127.0.0.1", "::1" }, options.BindToAddress);
    }

    [Fact]
    public void Switch_mappings_accept_the_equals_form()
    {
        Assert.Equal("2222", Bind(CommandLine("--port=2222")).Port);
    }

    [Fact]
    public void Without_configuration_the_stored_settings_are_used()
    {
        var effective = EffectiveListenSettings.Resolve(Stored(2200, "10.0.0.1"), Bind(Config()));

        Assert.Equal(2200, effective.Port);
        Assert.Equal(new[] { "10.0.0.1" }, effective.BindToAddress);
        Assert.Equal("database", effective.PortSource);
        Assert.Equal("database", effective.BindSource);
    }

    [Fact]
    public void Configuration_overrides_the_stored_port_and_bind_addresses_without_changing_the_stored_settings()
    {
        var stored = Stored(2200, "10.0.0.1");

        var effective = EffectiveListenSettings.Resolve(stored, Bind(Config(("SshServer:Port", "2222"), ("SshServer:BindToAddress", "127.0.0.1"))));

        Assert.Equal(2222, effective.Port);
        Assert.Equal(new[] { "127.0.0.1" }, effective.BindToAddress);
        Assert.Equal("configuration", effective.PortSource);
        Assert.Equal("configuration", effective.BindSource);
        Assert.Equal(2200, stored.ListenToPort);
        Assert.Equal(new[] { "10.0.0.1" }, stored.BindToAddress);
    }

    [Fact]
    public void Port_and_bind_are_overridden_independently()
    {
        var effective = EffectiveListenSettings.Resolve(Stored(2200, "10.0.0.1"), Bind(Config(("SshServer:Port", "2222"))));

        Assert.Equal(2222, effective.Port);
        Assert.Equal(new[] { "10.0.0.1" }, effective.BindToAddress);
        Assert.Equal("configuration", effective.PortSource);
        Assert.Equal("database", effective.BindSource);
    }

    [Fact]
    public void An_empty_configured_value_does_not_override()
    {
        var effective = EffectiveListenSettings.Resolve(Stored(2200), Bind(Config(("SshServer:Port", ""), ("SshServer:BindToAddress", ""))));

        Assert.Equal(2200, effective.Port);
        Assert.Equal("database", effective.PortSource);
        Assert.Equal("database", effective.BindSource);
    }

    [Theory]
    [InlineData("1", 1)]
    [InlineData("65535", 65535)]
    [InlineData(" 2222 ", 2222)]
    public void Valid_ports_are_accepted(string value, int expected)
    {
        Assert.Equal(expected, EffectiveListenSettings.Resolve(Stored(), new SshServerOptions { Port = value }).Port);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("-1")]
    [InlineData("abc")]
    [InlineData("22.5")]
    [InlineData("99999999999")]
    public void Invalid_configured_ports_are_rejected_with_a_clear_message(string value)
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => EffectiveListenSettings.Resolve(Stored(), new SshServerOptions { Port = value }));

        Assert.Contains("SshServer:Port", error.Message);
        Assert.Contains("1 to 65535", error.Message);
    }

    [Fact]
    public void An_invalid_stored_port_is_rejected()
    {
        Assert.Throws<InvalidOperationException>(() => EffectiveListenSettings.Resolve(Stored(70000), new SshServerOptions()));
    }

    [Fact]
    public void A_valid_configured_port_makes_an_invalid_stored_port_irrelevant()
    {
        Assert.Equal(2222, EffectiveListenSettings.Resolve(Stored(0), new SshServerOptions { Port = "2222" }).Port);
    }
}
