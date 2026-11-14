using FreeSftpSharp.Tests.WebUi;
using Microsoft.Extensions.Configuration;
using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace FreeSftpSharp.Tests.Logging;

/// <summary>The Serilog setup of both apps is in their appsettings.json (issue #33). These tests catch broken JSON.</summary>
public class LoggingConfigurationTests
{
    public static TheoryData<string> Apps => new() { "FxSshSftpServer.appsettings.json", "ServerConsoleApp.appsettings.json" };

    private static string SettingsPath(string name) => Path.Combine(AppContext.BaseDirectory, "AppSettings", name);

    private static Logger Create(string name)
    {
        var configuration = new ConfigurationBuilder().AddJsonFile(SettingsPath(name), optional: false).Build();
        // Same path handling as the apps (relative paths go to the app directory); the sinks are replaced below.
        var logger = new LoggerConfiguration().ReadFrom.Configuration(configuration);
        return logger.CreateLogger();
    }

    [Theory]
    [MemberData(nameof(Apps))]
    public void Default_level_is_Information_and_noisy_namespaces_are_Warning(string name)
    {
        // The sinks write into logs/ below the test directory.
        using var logger = Create(name);

        Assert.False(logger.IsEnabled(LogEventLevel.Debug));
        Assert.True(logger.IsEnabled(LogEventLevel.Information));

        var app = logger.ForContext(Constants.SourceContextPropertyName, "FxSsh.SshServerModule.HostedServer");
        Assert.True(app.IsEnabled(LogEventLevel.Information));

        foreach (var source in new[] { "Microsoft.AspNetCore.Routing.EndpointMiddleware", "Microsoft.EntityFrameworkCore.Query", "System.Net.Http.HttpClient", "Microsoft.AspNetCore" })
        {
            var noisy = logger.ForContext(Constants.SourceContextPropertyName, source);
            Assert.False(noisy.IsEnabled(LogEventLevel.Information), source);
            Assert.True(noisy.IsEnabled(LogEventLevel.Warning), source);
        }

        var lifetime = logger.ForContext(Constants.SourceContextPropertyName, "Microsoft.Hosting.Lifetime");
        Assert.True(lifetime.IsEnabled(LogEventLevel.Information));
    }

    [Theory]
    [MemberData(nameof(Apps))]
    public void Relative_log_paths_are_moved_to_the_app_directory(string name)
    {
        var configuration = new ConfigurationBuilder().AddJsonFile(SettingsPath(name), optional: false).Build();
        var fixedUp = LogFilePaths.MakeAbsolute(configuration);

        var paths = fixedUp.GetSection("Serilog:WriteTo").GetChildren()
            .Select(s => s["Args:path"]).Where(p => p is not null).ToList();
        Assert.NotEmpty(paths);
        Assert.All(paths, p => Assert.StartsWith(AppContext.BaseDirectory, p));
    }
    [Theory]
    [MemberData(nameof(Apps))]
    public void File_sink_paths_can_be_overridden_by_environment_variables(string name)
    {
        // Same keys as the environment variables Serilog__WriteTo__File__Args__path and ...__HtmlFile__Args__path.
        var dir = Path.Combine(Path.GetTempPath(), "fss-log-" + Guid.NewGuid().ToString("N"));
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddJsonFile(SettingsPath(name), optional: false)
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Serilog:WriteTo:File:Args:path"] = Path.Combine(dir, "log-.txt"),
                    ["Serilog:WriteTo:HtmlFile:Args:path"] = Path.Combine(dir, "html", "log.html"),
                }).Build();

            using (var logger = new LoggerConfiguration().ReadFrom.Configuration(LogFilePaths.MakeAbsolute(configuration)).CreateLogger())
                logger.Information("hello");

            Assert.NotEmpty(Directory.GetFiles(dir, "log-*.txt"));
            Assert.NotEmpty(Directory.GetFiles(Path.Combine(dir, "html"), "log*.html"));
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }
}

/// <summary>Starts the web host with the log path set by an environment variable (issue #114).</summary>
[Collection(AdminUiCollection.Name)]
public class LogPathEnvironmentVariableTests
{
    [Fact]
    public async Task Web_host_starts_and_writes_the_log_to_the_path_of_the_environment_variable()
    {
        var dir = Path.Combine(Path.GetTempPath(), "fss-log-" + Guid.NewGuid().ToString("N"));
        Environment.SetEnvironmentVariable("Serilog__WriteTo__File__Args__path", Path.Combine(dir, "log-.txt"));
        try
        {
            using (var factory = new AdminUiFactory())
            {
                using var client = factory.CreateBrowser();
                var response = await client.GetAsync("/Login", TestContext.Current.CancellationToken);
                Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
            }

            Log.CloseAndFlush();
            Assert.NotEmpty(Directory.GetFiles(dir, "log-*.txt"));
        }
        finally
        {
            Environment.SetEnvironmentVariable("Serilog__WriteTo__File__Args__path", null);
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }
}

/// <summary>Starts the web host normally and checks that it logs no warnings (issue #33).</summary>
[Collection(AdminUiCollection.Name)]
public class NormalStartLoggingTests
{
    [Fact]
    public async Task Normal_start_writes_no_warning_or_error_events()
    {
        InMemoryLogSink.Instance.Clear();
        // Program reads the Serilog sinks from the configuration; add the in-memory sink through environment variables.
        Environment.SetEnvironmentVariable("Serilog__Using__2", "FreeSftpSharp.Tests");
        Environment.SetEnvironmentVariable("Serilog__WriteTo__InMemory__Name", "InMemoryLog");
        try
        {
            using var factory = new AdminUiFactory();
            using var client = factory.CreateBrowser();
            var response = await client.GetAsync("/Login", TestContext.Current.CancellationToken);
            Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        }
        finally
        {
            Environment.SetEnvironmentVariable("Serilog__Using__2", null);
            Environment.SetEnvironmentVariable("Serilog__WriteTo__InMemory__Name", null);
        }

        var events = InMemoryLogSink.Instance.Snapshot();
        Assert.Contains(events, e => e.RenderMessage().Contains("Starting host service")); // the sink works
        var problems = events.Where(e => e.Level >= LogEventLevel.Warning)
            .Where(e => !IsExpectedUnencryptedKeyWarning(e))
            .Select(e => $"{e.Level}: {e.RenderMessage()}").ToList();
        Assert.True(problems.Count == 0, string.Join(Environment.NewLine, problems));
    }

    // Outside Windows the data protection keys are stored unencrypted (DataProtectionSetup), and ASP.NET Core
    // warns about that when it creates the first key. That warning is correct and expected on these platforms.
    private static bool IsExpectedUnencryptedKeyWarning(LogEvent e) =>
        !OperatingSystem.IsWindows()
        && e.Level == LogEventLevel.Warning
        && e.MessageTemplate.Text.Contains("No XML encryptor configured", StringComparison.Ordinal);
}
