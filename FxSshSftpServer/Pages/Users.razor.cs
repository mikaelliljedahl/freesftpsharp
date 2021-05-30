using FxSsh.SshServerModule;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using FxSshSftpServer.Components;

namespace FxSshSftpServer.Pages
{

    public partial class Users : ComponentBase
    {
        public List<User> AllUsers { get; set; }

        public User SelectedUser { get; set; }

        public string NewUsername { get; set; }

        public bool SelectedUserNotSaved { get; set; }
        public string newpassword { get; set; }

        public bool usekeyfile { get; set; }

        protected override async Task OnAfterRenderAsync(bool firstRender)
        {
            if (firstRender)
            {
                AllUsers = HostedServer.settingsrepo.GetAllUsers();
                _ = InvokeAsync(StateHasChanged);
            }
        }

        void OnUserSelected()
        {
            SelectedUserNotSaved = false;
            
        }

        private async Task LoadUser(string username)
        {
            SelectedUser = HostedServer.settingsrepo.GetUser(username);
            SelectedUserNotSaved = false;
        }

        private async Task CreateKeyForUser()
        {

            var csp = new System.Security.Cryptography.RSACryptoServiceProvider(4096);

            var rsakeydata = csp.ExportCspBlob(true);
            var publicKey = csp.ExportRSAPublicKey();

            SelectedUser.RsaKey = Convert.ToBase64String(publicKey);
            JSRuntime.SaveFile(rsakeydata, $"{SelectedUser.Username}.ppk");
        }

        private async Task CreateUser()
        {
            SelectedUser = new User();
            SelectedUser.Username = NewUsername;
            AllUsers.Add(SelectedUser);
            SelectedUserNotSaved = true;
            // HostedServer.settingsrepo.AddUser(new User() { Username = NewUsername });
        }

        void OnChangeKeyfileOrPassword(bool? value)
        {
            _ = InvokeAsync(StateHasChanged);
        }
        private async Task SaveUser()
        {
            if (!string.IsNullOrWhiteSpace(newpassword))
            {
                var sha256 = new SHA256CryptoServiceProvider();
                var pwhashed = sha256.ComputeHash(System.Text.Encoding.ASCII.GetBytes(newpassword));
                var base64encoded = Convert.ToBase64String(pwhashed);
                SelectedUser.HashedPassword = base64encoded;
            }

            if (SelectedUserNotSaved)
            {
                HostedServer.settingsrepo.AddUser(SelectedUser);
            }
            else
            {
                HostedServer.settingsrepo.UpdateUser(SelectedUser);
            }
        }
    }

}

