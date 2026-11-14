using SshServer.Interfaces.Security;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace FxSshSftpServer.Security
{
    /// <summary>
    /// <c>FxSshSftpServer --hash-admin-password</c>: reads a password and prints the configuration value for
    /// <c>AdminAuth:PasswordHash</c>. The password is never printed.
    /// </summary>
    public static class AdminPasswordCommand
    {
        public const string Switch = "--hash-admin-password";
        public const int MinimumPasswordLength = 8;

        public static bool IsRequested(string[] args) =>
            args.Any(a => string.Equals(a, Switch, StringComparison.OrdinalIgnoreCase));

        /// <summary>Runs the command on the console. Returns the process exit code.</summary>
        public static int RunOnConsole() =>
            Run(Console.In, Console.Out, Console.Error, interactive: !Console.IsInputRedirected);

        public static int Run(TextReader input, TextWriter output, TextWriter error, bool interactive)
        {
            string password;
            if (interactive)
            {
                password = ReadHidden(error, "Admin password: ");
                var repeated = ReadHidden(error, "Repeat password: ");
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

            if (string.IsNullOrEmpty(password) || password.Length < MinimumPasswordLength)
            {
                error.WriteLine($"The password must have at least {MinimumPasswordLength} characters.");
                return 1;
            }

            var hash = PasswordHasher.Hash(password);
            output.WriteLine("Add the hash to the configuration, for example as an environment variable:");
            output.WriteLine();
            output.WriteLine($"AdminAuth__PasswordHash={hash}");
            output.WriteLine();
            output.WriteLine("or in appsettings.json / user secrets:");
            output.WriteLine();
            output.WriteLine($"\"AdminAuth\": {{ \"UserName\": \"admin\", \"PasswordHash\": \"{hash}\" }}");
            return 0;
        }

        internal static string ReadHidden(TextWriter prompt, string text)
        {
            prompt.Write(text);
            var builder = new StringBuilder();
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                    break;
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (builder.Length > 0)
                        builder.Length--;
                    continue;
                }
                if (!char.IsControl(key.KeyChar))
                    builder.Append(key.KeyChar);
            }
            prompt.WriteLine();
            return builder.ToString();
        }
    }
}
