using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;

namespace FxSsh.SshServerModule
{
    /// <summary>
    /// The <c>SshServer</c> configuration section (appsettings.json, environment variables <c>SshServer__Port</c> and
    /// <c>SshServer__BindToAddress</c>, command line <c>--port</c> and <c>--bind</c>). A value that is set here overrides the
    /// stored <c>ServerSettings</c> at runtime; it is never written to the settings database.
    /// </summary>
    public sealed class SshServerOptions
    {
        public const string SectionName = "SshServer";

        /// <summary>The listen port as text (1-65535). Null or empty: use the stored setting. It is validated at start.</summary>
        public string Port { get; set; }

        /// <summary>The local addresses to listen on. Null or empty: use the stored setting.</summary>
        public List<string> BindToAddress { get; set; }

        /// <summary>Command-line shortcuts for <c>AddCommandLine(args, SshServerOptions.SwitchMappings)</c>.</summary>
        public static IDictionary<string, string> SwitchMappings { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["--port"] = SectionName + ":Port",
            ["--bind"] = SectionName + ":BindToAddress",
        };

        /// <summary>
        /// Reads the section. <c>BindToAddress</c> can be a comma separated string (<c>SshServer__BindToAddress=127.0.0.1,::1</c>,
        /// <c>--bind 127.0.0.1,::1</c>) or an array (JSON, or <c>SshServer__BindToAddress__0</c>).
        /// </summary>
        public static SshServerOptions FromConfiguration(IConfiguration configuration)
        {
            var section = configuration.GetSection(SectionName);
            var options = new SshServerOptions { Port = section["Port"] };

            var bind = section.GetSection("BindToAddress");
            var raw = bind.Value != null
                ? new[] { bind.Value }
                : bind.GetChildren().Select(c => c.Value).Where(v => v != null).ToArray();
            options.BindToAddress = raw
                .SelectMany(v => v.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                .ToList();
            return options;
        }
    }

    public static class SshServerOptionsServiceCollectionExtensions
    {
        /// <summary>
        /// Binds <see cref="SshServerOptions"/> from the <c>SshServer</c> section of the application configuration, and the
        /// <see cref="global::SshServerModule.Proxy.ProxyProtocolOptions"/> from the <c>Proxy</c> section.
        /// </summary>
        public static IServiceCollection AddSshServerListenOptions(this IServiceCollection services)
        {
            services.AddOptions<SshServerOptions>()
                .Configure<IConfiguration>((options, configuration) =>
                {
                    var bound = SshServerOptions.FromConfiguration(configuration);
                    options.Port = bound.Port;
                    options.BindToAddress = bound.BindToAddress;
                });
            // The PROXY protocol of a load balancer (#75): off until Proxy:AllowedSources is set.
            services.TryAddSingleton(sp => global::SshServerModule.Proxy.ProxyProtocolOptions.FromConfiguration(sp.GetRequiredService<IConfiguration>()));
            return services;
        }
    }
}
