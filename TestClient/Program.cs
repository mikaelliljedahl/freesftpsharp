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

            var sha256 = new System.Security.Cryptography.SHA256CryptoServiceProvider();
            var pwhashed = sha256.ComputeHash(System.Text.Encoding.ASCII.GetBytes(testPassword));

            var pwhashedstring = Convert.ToBase64String(pwhashed);

            var connInfo = new ConnectionInfo(IPAddress.Loopback.ToString(), 22, testUsername,
                new AuthenticationMethod[]
                {
                    // Password auth
                    new PasswordAuthenticationMethod(testUsername, testPassword)
                }
            );

            using var sftpclient = new SftpClient(connInfo);
            sftpclient.Connect();
            sftpclient.ListDirectory("/");
            sftpclient.Disconnect();

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
                        Console.Write($"exec: {cmd}, result: {result}");
                    }
                }
            }
            Console.ReadLine();
        }
    }
}