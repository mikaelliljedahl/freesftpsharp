using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using SshServer.Interfaces.Users;
using SshServer.Interfaces;

namespace FxSsh.SshServerModule.Cli
{
    /// <summary>
    /// <c>ServerConsoleApp user add|list|remove</c>. Parses the arguments and calls
    /// <see cref="UserAdministrationService"/>, the same service as the admin UI. It never starts the server.
    /// Exit codes: 0 ok, 1 the operation failed (message on the error stream), 2 wrong usage.
    /// </summary>
    public static class UserCommand
    {
        public const string Name = "user";

        public const string Usage =
            "Usage:\n" +
            "  ServerConsoleApp user add <name> --root <dir> [--password-stdin | --public-key <file>]\n" +
            "  ServerConsoleApp user list\n" +
            "  ServerConsoleApp user remove <name>\n" +
            "\n" +
            "The password is read from stdin (--password-stdin) or asked for on a terminal, never from an argument.";

        public static bool IsRequested(string[] args) =>
            args.Length > 0 && string.Equals(args[0], Name, StringComparison.OrdinalIgnoreCase);

        /// <param name="args">All arguments, starting with <c>user</c>.</param>
        /// <param name="input">Standard input (the password with <c>--password-stdin</c>).</param>
        /// <param name="interactive">True when stdin is a terminal: the password is asked for with <paramref name="promptHidden"/>.</param>
        /// <param name="promptHidden">Shows the text and reads a line without echo.</param>
        public static int Run(string[] args, UserAdministrationService users, TextReader input, TextWriter output, TextWriter error,
            bool interactive, Func<string, string> promptHidden)
        {
            var rest = args.Skip(1).ToList();
            if (rest.Count == 0)
                return UsageError(error, "Missing command.");

            var command = rest[0].ToLowerInvariant();
            rest.RemoveAt(0);
            try
            {
                return command switch
                {
                    "add" => Add(rest, users, input, output, error, interactive, promptHidden),
                    "list" => List(rest, users, output, error),
                    "remove" => Remove(rest, users, output, error),
                    _ => UsageError(error, $"Unknown command '{command}'."),
                };
            }
            catch (UserAdministrationException ex)
            {
                error.WriteLine(ex.Message);
                return 1;
            }
        }

        private static int Add(List<string> args, UserAdministrationService users, TextReader input, TextWriter output, TextWriter error,
            bool interactive, Func<string, string> promptHidden)
        {
            string root = null, keyFile = null;
            var passwordStdin = false;
            var positional = new List<string>();
            for (var i = 0; i < args.Count; i++)
            {
                var arg = args[i];
                if (arg == "--password-stdin")
                    passwordStdin = true;
                else if (TryOption(args, ref i, "--root", out var r, out var missing1))
                    root = missing1 ? null : r;
                else if (TryOption(args, ref i, "--public-key", out var k, out var missing2))
                    keyFile = missing2 ? null : k;
                else if (arg.StartsWith("--", StringComparison.Ordinal))
                    return UsageError(error, $"Unknown option '{arg}'.");
                else
                    positional.Add(arg);
            }

            if (positional.Count != 1)
                return UsageError(error, "Give exactly one user name.");
            if (string.IsNullOrWhiteSpace(root))
                return UsageError(error, "--root <dir> is required.");
            if (passwordStdin && keyFile != null)
                return UsageError(error, "Use either --password-stdin or --public-key, not both.");

            var name = positional[0];
            string password = null, keyText = null;
            if (keyFile != null)
            {
                try
                {
                    keyText = File.ReadAllText(keyFile);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    error.WriteLine($"The public key file '{keyFile}' cannot be read: {ex.Message}");
                    return 1;
                }
            }
            else if (passwordStdin)
            {
                password = input.ReadLine()?.TrimEnd('\r');
                if (password == null)
                {
                    error.WriteLine("No password on stdin.");
                    return 1;
                }
            }
            else if (interactive)
            {
                // Check the cheap rules before asking for a password.
                var nameError = UserAdministrationService.ValidateUserName(name);
                if (nameError != null)
                {
                    error.WriteLine(nameError);
                    return 1;
                }
                password = promptHidden("Password: ");
                if (!string.Equals(password, promptHidden("Repeat password: "), StringComparison.Ordinal))
                {
                    error.WriteLine("The passwords do not match.");
                    return 1;
                }
            }
            else
            {
                return UsageError(error, "Give --password-stdin or --public-key (stdin is not a terminal, so there is no prompt).");
            }

            var user = users.Create(name, root, password, keyText);
            output.WriteLine($"User '{user.Username}' added. Root directory: {user.UserRootDirectory}");
            return 0;
        }

        private static int List(List<string> args, UserAdministrationService users, TextWriter output, TextWriter error)
        {
            if (args.Count > 0)
                return UsageError(error, "'user list' takes no arguments.");
            var all = users.List();
            if (all.Count == 0)
            {
                output.WriteLine("No users.");
                return 0;
            }
            var width = Math.Max("NAME".Length, all.Max(u => u.Username?.Length ?? 0));
            output.WriteLine($"{"NAME".PadRight(width)}  {"LOGIN",-14}  ROOT");
            foreach (var u in all)
            {
                var login = string.Join("+", new[]
                {
                    string.IsNullOrWhiteSpace(u.HashedPassword) ? null : "password",
                    string.IsNullOrWhiteSpace(u.RsaPublicKey) ? null : "key",
                }.Where(x => x != null));
                output.WriteLine($"{(u.Username ?? "").PadRight(width)}  {(login.Length == 0 ? "none" : login),-14}  {u.UserRootDirectory}");
            }
            return 0;
        }

        private static int Remove(List<string> args, UserAdministrationService users, TextWriter output, TextWriter error)
        {
            if (args.Count != 1 || args[0].StartsWith("--", StringComparison.Ordinal))
                return UsageError(error, "Give exactly one user name.");
            var name = args[0];
            var existing = users.List().FirstOrDefault(u => string.Equals(u.Username, name, StringComparison.OrdinalIgnoreCase));
            if (existing == null || !users.Remove(existing.Username))
            {
                error.WriteLine($"The user '{name}' does not exist.");
                return 1;
            }
            output.WriteLine($"User '{existing.Username}' removed. The files in {existing.UserRootDirectory} were not deleted.");
            return 0;
        }

        // --name value or --name=value. missing is true when the value is absent.
        private static bool TryOption(List<string> args, ref int index, string name, out string value, out bool missing)
        {
            value = null;
            missing = false;
            var arg = args[index];
            if (arg == name)
            {
                if (index + 1 < args.Count)
                    value = args[++index];
                else
                    missing = true;
                return true;
            }
            if (arg.StartsWith(name + "=", StringComparison.Ordinal))
            {
                value = arg.Substring(name.Length + 1);
                return true;
            }
            return false;
        }

        private static int UsageError(TextWriter error, string message)
        {
            error.WriteLine(message);
            error.WriteLine(Usage);
            return 2;
        }
    }
}
