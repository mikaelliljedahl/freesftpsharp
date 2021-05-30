using FxSsh.Services;
using FxSsh.SshServerModule.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FxSsh.SshServerModule
{
    public class HostedServer : IHostedService
    {
        public static SettingsRepository settingsrepo;
        private SshServer server;
        
        private readonly ILogger _logger;

        public HostedServer(ILogger<HostedServer> logger)
        {
            _logger = logger;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {

            settingsrepo = new SettingsRepository();
            var port = settingsrepo.ServerSettings.ListenToPort;

            server = new SshServer(new SshServerSettings { Port = port, ServerBanner = "FxSSHSFTP", IdleTimeout = settingsrepo.ServerSettings.IdleTimeout });
            server.AddHostKey("ssh-rsa", settingsrepo.ServerSettings.ServerRsaKey);


            //server.AddHostKey("ssh-rsa", rfc);
            //server.AddHostKey("ssh-dss", publickey);

            //server.AddHostKey("ssh-rsa", "BwIAAACkAABSU0EyAAQAAAEAAQADKjiW5UyIad8ITutLjcdtejF4wPA1dk1JFHesDMEhU9pGUUs+HPTmSn67ar3UvVj/1t/+YK01FzMtgq4GHKzQHHl2+N+onWK4qbIAMgC6vIcs8u3d38f3NFUfX+lMnngeyxzbYITtDeVVXcLnFd7NgaOcouQyGzYrHBPbyEivswsnqcnF4JpUTln29E1mqt0a49GL8kZtDfNrdRSt/opeexhCuzSjLPuwzTPc6fKgMc6q4MBDBk53vrFY2LtGALrpg3tuydh3RbMLcrVyTNT+7st37goubQ2xWGgkLvo+TZqu3yutxr1oLSaPMSmf9bTACMi5QDicB3CaWNe9eU73MzhXaFLpNpBpLfIuhUaZ3COlMazs7H9LCJMXEL95V6ydnATf7tyO0O+jQp7hgYJdRLR3kNAKT0HU8enE9ZbQEXG88hSCbpf1PvFUytb1QBcotDy6bQ6vTtEAZV+XwnUGwFRexERWuu9XD6eVkYjA4Y3PGtSXbsvhwgH0mTlBOuH4soy8MV4dxGkxM8fIMM0NISTYrPvCeyozSq+NDkekXztFau7zdVEYmhCqIjeMNmRGuiEo8ppJYj4CvR1hc8xScUIw7N4OnLISeAdptm97ADxZqWWFZHno7j7rbNsq5ysdx08OtplghFPx4vNHlS09LwdStumtUel5oIEVMYv+yWBYSPPZBcVY5YFyZFJzd0AOkVtUbEbLuzRs5AtKZG01Ip/8+pZQvJvdbBMLT1BUvHTrccuRbY03SHIaUM3cTUc=");
            //server.AddHostKey("ssh-dss", "BwIAAAAiAABEU1MyAAQAAG+6KQWB+crih2Ivb6CZsMe/7NHLimiTl0ap97KyBoBOs1amqXB8IRwI2h9A10R/v0BHmdyjwe0c0lPsegqDuBUfD2VmsDgrZ/i78t7EJ6Sb6m2lVQfTT0w7FYgVk3J1Deygh7UcbIbDoQ+refeRNM7CjSKtdR+/zIwO3Qub2qH+p6iol2iAlh0LP+cw+XlH0LW5YKPqOXOLgMIiO+48HZjvV67pn5LDubxru3ZQLvjOcDY0pqi5g7AJ3wkLq5dezzDOOun72E42uUHTXOzo+Ct6OZXFP53ZzOfjNw0SiL66353c9igBiRMTGn2gZ+au0jMeIaSsQNjQmWD+Lnri39n0gSCXurDaPkec+uaufGSG9tWgGnBdJhUDqwab8P/Ipvo5lS5p6PlzAQAAACqx1Nid0Ea0YAuYPhg+YolsJ/ce");
            server.ConnectionAccepted += OnConnectionAccepted;

            server.Start();
            await Task.Delay(1);
           
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            server.ConnectionAccepted -= OnConnectionAccepted;
            server.Stop();
            server.Dispose();
            settingsrepo.Dispose();
            await Task.Delay(1);
           
        }

        void OnConnectionAccepted(object sender, Session e)
        {
            _logger.LogInformation("Accepted a client.");

            e.ServiceRegistered += OnServiceRegistered;
        }


        void OnServiceRegistered(object sender, SshService e)
        {
            var session = (Session)sender;
            _logger.LogInformation("Session {0} requesting {1}.",
                BitConverter.ToString(session.SessionId).Replace("-", ""), e.GetType().Name);

            if (e is UserAuthService)
            {
                var service = (UserAuthService)e;
                service.UserAuth += OnUserAuth;
            }
            else if (e is ConnectionService)
            {
                var service = (ConnectionService)e;
                

                service.SessionRequest += OnSessionRequestOpened; // adding SFTP session initiation support

                if (settingsrepo.ServerSettings.EnableCommand)
                    service.CommandOpened += OnServiceCommandOpened;
                if (settingsrepo.ServerSettings.EnableDirectTcpIp)
                {
                    service.TcpForwardRequest += OnDirectTcpIpReceived;
                    //service.DirectTcpIpReceived += OnDirectTcpIpReceived;
                }

            }
        }

        

        static void OnDirectTcpIpReceived(object sender, TcpRequestArgs e)
        {
            Console.WriteLine("Received a request to forward data to {0}:{1}", e.Host, e.Port);

            var allow = true;  // func(e.Host, e.Port, e.AttachedUserauthArgs);

            if (!allow)
                return;
            
            var tcp = new TcpForwardService(e.Host, e.Port, e.OriginatorIP, e.OriginatorPort);
            e.Channel.DataReceived += (ss, ee) => tcp.OnData(ee);
            e.Channel.CloseReceived += (ss, ee) => tcp.OnClose();
            tcp.DataReceived += (ss, ee) => e.Channel.SendData(ee);
            tcp.CloseReceived += (ss, ee) => e.Channel.SendClose();
            tcp.Start();
        }

        void OnUserAuth(object sender, UserAuthArgs e)
        {

            var user = settingsrepo.GetUser(e.Username);
            if (user == null)
            {
                e.Result = false;
                return;
            }

            e.Result = user.VerifyUserIpWhitelisted(e.Session.RemoteEndpoint);

            if (!e.Result)
            {
                _logger.LogInformation("Client {0} IP-banned: {2}", e.Session.RemoteEndpoint);
                return;

            }

            if (e is PKUserAuthArgs)
            {
                var pk = e as PKUserAuthArgs;
                //  verify key against user data
                e.Result = user.VerifyUserKey(pk.Key, pk.Fingerprint, pk.KeyAlgorithm);
                

                _logger.LogInformation("Client {0} fingerprint: {1}. Successful: {2}", pk.KeyAlgorithm, pk.Fingerprint, e.Result);
            }
            else if (e is PasswordUserAuthArgs)
            {
                var pw = e as PasswordUserAuthArgs;

                // verify password against user data
              
                e.Result = user.VerifyUserPassword(pw.Password);


                //e.Password 
                _logger.LogInformation("Client {0} password length: {1}. Successful: {2}", pw.Username, pw.Password?.Length, e.Result);
            }

        }



        void OnSessionRequestOpened(object sender, SessionRequestedArgs e)
        {
            
            _logger.LogInformation("Channel {0} requested session: \"{1}\".", e.Channel.ServerChannelId, e.CommandText);

            if (e.SubSystemName == "sftp")
            {

                InitializeSftp(e.Channel, e.AttachedUserAuthArgs.Username);

            }
            else
            {
                e.Channel.SendData(Encoding.UTF8.GetBytes($"You ran {e.CommandText}\n"));
                e.Channel.SendClose();
            }
        }

        private void InitializeSftp(SessionChannel channel, string username)
        {
            var user = settingsrepo.GetUser(username);
            if (user != null)
            {
                // check IP user.WhitelistedIps
                

                SftpSubsystem sftpsub = new SftpSubsystem(_logger, channel.ClientChannelId, user.UserRootDirectory);
                channel.DataReceived += (ss, ee) => sftpsub.OnInput(ee);
                sftpsub.OnOutput += (ss, ee) => channel.SendData(ee);
                sftpsub.OnClose += (ss, ee) => channel.SendClose(null);

            }
        }

        void OnServiceCommandOpened(object sender, CommandRequestedArgs e)
        {

            Console.WriteLine($"Channel {e.Channel.ServerChannelId} runs {e.SubSystemName}: \"{e.CommandText}\".");

            // var allow = true;  // func(e.ShellType, e.CommandText, e.AttachedUserauthArgs);

            if (!e.AttachedUserAuthArgs.Result) // TODO - check access rights per service
                return;

            if (e.SubSystemName == "shell")
            {
                // requirements: Windows 10 RedStone 5, 1809
                // also, you can call powershell.exe
                //var terminal = new Terminal("cmd.exe", windowWidth, windowHeight);

                //e.Channel.DataReceived += (ss, ee) => terminal.OnInput(ee);
                //e.Channel.CloseReceived += (ss, ee) => terminal.OnClose();
                //terminal.DataReceived += (ss, ee) => e.Channel.SendData(ee);
                //terminal.CloseReceived += (ss, ee) => e.Channel.SendClose(ee);

                //terminal.Run();
            }
            else if (e.SubSystemName == "exec")
            {
                //var parser = new Regex(@"(?<cmd>git-receive-pack|git-upload-pack|git-upload-archive) \'/?(?<proj>.+)\.git\'");
                //var match = parser.Match(e.CommandText);
                //var command = match.Groups["cmd"].Value;
                //var project = match.Groups["proj"].Value;

            }
            else if (e.SubSystemName == "sftp")
            {
                // do something more
                if (e.AttachedUserAuthArgs.Result)
                    InitializeSftp(e.Channel, e.AttachedUserAuthArgs.Username);

                return;
            }


            _logger.LogInformation($"Channel {e.Channel.ServerChannelId} runs command: \"{e.CommandText}\". on subsystem: {e.SubSystemName}");

            e.Channel.SendData(Encoding.UTF8.GetBytes($"You ran {e.CommandText}\n"));
            e.Channel.SendClose();
        }




    }
}
