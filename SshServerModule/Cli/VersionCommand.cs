using System;
using System.Reflection;

namespace FxSsh.SshServerModule.Cli
{
    /// <summary>
    /// <c>--version</c>: prints the version of the program and exits. A release build gets the version from the git
    /// tag (<c>-p:Version=1.2.3</c> at publish); a local build reports its default version.
    /// </summary>
    public static class VersionCommand
    {
        public const string Switch = "--version";

        public static bool IsRequested(string[] args) =>
            args.Length == 1 && string.Equals(args[0], Switch, StringComparison.OrdinalIgnoreCase);

        /// <summary>The informational version of <paramref name="assembly"/> without the "+commit" build metadata.</summary>
        public static string Describe(Assembly assembly)
        {
            var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            var version = string.IsNullOrWhiteSpace(informational)
                ? assembly.GetName().Version?.ToString(3) ?? "0.0.0"
                : informational;
            var plus = version.IndexOf('+');
            return plus >= 0 ? version[..plus] : version;
        }
    }
}
