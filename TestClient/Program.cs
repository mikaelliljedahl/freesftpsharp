using Renci.SshNet;
using System;
using System.Net;

namespace TestClient
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var testUsername = "test_person";
            var testPassword = "1234";
            var connInfo = new ConnectionInfo(IPAddress.Loopback.ToString(), 4022, testUsername,
                new AuthenticationMethod[]
                {
                    // Password auth
                    new PasswordAuthenticationMethod(testUsername, testPassword)
                }
            );
            using (var sshClient = new SshClient(connInfo))
            {
                sshClient.Connect();
                var commands = new[] { "info", "hello", "rm -rf /" };
                foreach (var cmd in commands)
                {
                    using (var sshCmd = sshClient.CreateCommand(cmd))
                    {
                        sshCmd.Execute();
                        var result = sshCmd.Result;
                        Console.WriteLine($"exec: {cmd}, result: {result}");
                    }
                }
            }
        }
    }
}