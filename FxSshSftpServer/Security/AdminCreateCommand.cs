using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces.Admins;
using SshServer.Settings.Sql;
using SshServerModule.Events;

namespace FxSshSftpServer.Security
{
    /// <summary>
    /// <c>FxSshSftpServer --create-admin [name]</c>: creates a super admin in the settings database (the same database
    /// and configuration as the server) and exits. It asks for the password like <see cref="AdminPasswordCommand"/>,
    /// or reads one line from stdin when the input is redirected. The password is never printed.
    /// </summary>
    public static class AdminCreateCommand
    {
        public const string Switch = "--create-admin";

        public static bool IsRequested(string[] args) =>
            args.Any(a => string.Equals(a, Switch, StringComparison.OrdinalIgnoreCase));

        /// <summary>Runs the command with the configuration of the server. Returns the process exit code.</summary>
        public static int RunOnConsole(string[] args)
        {
            try
            {
                var configuration = WebApplication.CreateBuilder(args).Configuration;
                // With the event bus, so that the audit log has the new administrator. Disposing the provider delivers it.
                using var provider = new ServiceCollection().AddLogging().AddSshServerSettings(configuration).AddSshServerEvents()
                    .BuildServiceProvider();
                return RunAsync(args, provider.GetRequiredService<AdminAdministrationService>(),
                    Console.In, Console.Out, Console.Error, interactive: !Console.IsInputRedirected, CancellationToken.None)
                    .GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Creating the administrator failed: {ex.Message}");
                return 1;
            }
        }

        public static async Task<int> RunAsync(string[] args, AdminAdministrationService administration, TextReader input,
            TextWriter output, TextWriter error, bool interactive, CancellationToken ct)
        {
            var index = Array.FindIndex(args, a => string.Equals(a, Switch, StringComparison.OrdinalIgnoreCase));
            var name = index >= 0 && index + 1 < args.Length && !args[index + 1].StartsWith("--", StringComparison.Ordinal)
                ? args[index + 1]
                : null;
            if (name == null)
            {
                if (!interactive)
                {
                    error.WriteLine($"Usage: FxSshSftpServer {Switch} <name> (the password is read from stdin).");
                    return 1;
                }
                error.Write("Admin user name: ");
                name = input.ReadLine();
            }

            string password;
            if (interactive)
            {
                password = AdminPasswordCommand.ReadHidden(error, "Admin password: ");
                var repeated = AdminPasswordCommand.ReadHidden(error, "Repeat password: ");
                if (!string.Equals(password, repeated, StringComparison.Ordinal))
                {
                    error.WriteLine("The passwords do not match.");
                    return 1;
                }
            }
            else
            {
                password = input.ReadLine();
            }

            try
            {
                var admin = await administration.CreateAdminAsync(AdminActor.System,
                    new AdminInput(name ?? "") { Permissions = AdminPermissions.SuperAdmin }, password ?? "", ct);
                output.WriteLine($"The super admin '{admin.Username}' was created. Log in to the admin UI with it.");
                return 0;
            }
            catch (AdminAdministrationException ex)
            {
                error.WriteLine(ex.Message);
                return 1;
            }
        }
    }
}
