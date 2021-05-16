using FxSsh;
using FxSsh.Messages.Connection;
using FxSsh.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FxSsh.SshServerLoader
{
    public class HostedSftpServer : IHostedService
    {
        private SettingsRepository settingsrepo;
        private SshServer server;
        
        private readonly ILogger _logger;

        public HostedSftpServer(ILogger<HostedSftpServer> logger)
        {
            _logger = logger;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {

            settingsrepo = new SettingsRepository();
            var port = settingsrepo.ServerSettings.ListenToPort;

            server = new SshServer(new SshServerSettings { Port = port, ServerBanner = "FxSSH-2.0-OpenSSH_7.1" });
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
                service.CommandOpened += OnServiceCommandOpened;
                
                
                //service.TcpForwardRequest += OnDirectTcpIpReceived
                //service.DirectTcpIpReceived += OnDirectTcpIpReceived;

            }
        }

        void OnUserAuth(object sender, UserAuthArgs e)
        {
            if (e is PKUserAuthArgs)
            {
                var pk = e as PKUserAuthArgs;
                _logger.LogInformation("Client {0} fingerprint: {1}.", pk.KeyAlgorithm, pk.Fingerprint);
            }
            else if (e is PasswordUserAuthArgs)
            {
                var pw = e as PasswordUserAuthArgs;
                _logger.LogInformation("Client {0} password length: {1}.", pw.Username, pw.Password?.Length);
            }

            e.Result = true;
        }



     
        void OnServiceCommandOpened(object sender, CommandRequestedArgs e)
        {

            _logger.LogInformation("Channel {0} runs command: \"{1}\".", e.Channel.ServerChannelId, e.CommandText);
            e.Channel.SendData(Encoding.UTF8.GetBytes($"You ran {e.CommandText}\n"));
            e.Channel.SendClose();
        }

    }
}
