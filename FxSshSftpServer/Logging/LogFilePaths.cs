using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Extensions.Configuration;

/// <summary>
/// Relative log file paths in the Serilog configuration (<c>path</c> argument of a sink) are resolved against
/// <see cref="AppContext.BaseDirectory"/>, not the current directory. Running from source then writes the logs to
/// <c>bin/.../logs</c> and not into the repository directory. Absolute paths are not changed.
/// </summary>
internal static class LogFilePaths
{
    public static IConfiguration MakeAbsolute(IConfiguration configuration)
    {
        var overrides = new Dictionary<string, string>();
        foreach (var sink in configuration.GetSection("Serilog:WriteTo").GetChildren())
        {
            var key = sink.Path + ":Args:path";
            var path = configuration[key];
            if (!string.IsNullOrWhiteSpace(path) && !Path.IsPathRooted(path))
                overrides[key] = Path.Combine(AppContext.BaseDirectory, path);
        }

        return overrides.Count == 0
            ? configuration
            : new ConfigurationBuilder().AddConfiguration(configuration).AddInMemoryCollection(overrides).Build();
    }
}
