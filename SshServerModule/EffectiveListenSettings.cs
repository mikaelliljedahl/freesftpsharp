using SshServer.Interfaces;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace FxSsh.SshServerModule
{
    /// <summary>The port and bind addresses the server uses: configuration (<see cref="SshServerOptions"/>) over the stored settings.</summary>
    public sealed record EffectiveListenSettings(
        int Port, IReadOnlyList<string> BindToAddress, bool PortFromConfiguration, bool BindFromConfiguration)
    {
        public string PortSource => PortFromConfiguration ? "configuration" : "database";
        public string BindSource => BindFromConfiguration ? "configuration" : "database";

        /// <exception cref="InvalidOperationException">The port is not a whole number from 1 to 65535.</exception>
        public static EffectiveListenSettings Resolve(ServerSettings stored, SshServerOptions options)
        {
            var portFromConfiguration = !string.IsNullOrWhiteSpace(options?.Port);
            int port;
            if (portFromConfiguration)
            {
                if (!int.TryParse(options.Port.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out port) || port < 1 || port > 65535)
                    throw new InvalidOperationException(
                        $"Invalid port \"{options.Port}\" in the configuration (SshServer:Port or --port). Use a whole number from 1 to 65535.");
            }
            else
            {
                port = stored.ListenToPort;
                if (port < 1 || port > 65535)
                    throw new InvalidOperationException(
                        $"Invalid port {port} in the stored settings (ListenToPort). Use a number from 1 to 65535, or set SshServer:Port.");
            }

            var bindFromConfiguration = options?.BindToAddress is { Count: > 0 } configured && configured.Any(e => !string.IsNullOrWhiteSpace(e));
            IReadOnlyList<string> bind = bindFromConfiguration ? options.BindToAddress : (stored.BindToAddress ?? new List<string>());
            return new EffectiveListenSettings(port, bind, portFromConfiguration, bindFromConfiguration);
        }
    }
}
