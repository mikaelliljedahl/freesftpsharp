using FxSsh.SshServerModule;
using FxSshSftpServer.Components;
using Microsoft.AspNetCore.Components;
using SshServer.Interfaces;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace FxSshSftpServer.Pages
{

    public partial class Users : ComponentBase
    {
        [Inject]
        public ISettingsRepository settingsRepository { get; set; }
        public List<User> AllUsers { get; set; }

        public User SelectedUser { get; set; }

        public string NewUsername { get; set; }

        public bool SelectedUserNotSaved { get; set; }
        public string newpassword { get; set; }

        public string InfoText { get; set; }
        public bool usekeyfile { get; set; }

        protected override void OnAfterRender(bool firstRender)
        {
            if (firstRender)
            {
                AllUsers = settingsRepository.GetAllUsers();
                _ = InvokeAsync(StateHasChanged);
            }
        }

        void OnUserSelected()
        {
            SelectedUserNotSaved = false;

            if (!string.IsNullOrWhiteSpace(SelectedUser.RsaPublicKey))
                usekeyfile = true;
            else
                usekeyfile = false;

            InfoText = "";
        }

        private void LoadUser(string username)
        {
            SelectedUser = settingsRepository.GetUser(username);
            SelectedUserNotSaved = false;
        }
        private void RemoveUser()
        {
            var removesuccess = settingsRepository.RemoveUser(SelectedUser.Username);

            if (removesuccess)
            {
                InfoText = $"User {SelectedUser.Username} was deleted";
                SelectedUser = null;
                AllUsers = settingsRepository.GetAllUsers();
                
            }
            else
                InfoText = $"Error deleting user {SelectedUser.Username}";

            _ = InvokeAsync(StateHasChanged);
        }

        private async Task CreateKeyForUser()
        {
            var csp = new System.Security.Cryptography.RSACryptoServiceProvider(1024);

            var rsakeyparam = csp.ExportParameters(true);

            var privkey = RSAConverter.ExportPrivateKey(csp);
            //var publicKey = RSAConverter.ExportPublicKey(csp);

            var publickeybytes = csp.ExportCspBlob(false);

            var publicKey = Convert.ToBase64String(publickeybytes);

            SelectedUser.RsaPublicKey = publicKey;

            var rsakeydata = System.Text.Encoding.UTF8.GetBytes(privkey);

            await JSRuntime.SaveFile(rsakeydata, $"{SelectedUser.Username}.pem");
            SaveUser();
        }

        private void CreateUser()
        {
            SelectedUser = new User();
            SelectedUser.Username = NewUsername;
            AllUsers.Add(SelectedUser);
            SelectedUserNotSaved = true;
            usekeyfile = false;
            // HostedServer.settingsrepo.AddUser(new User() { Username = NewUsername });
        }

        void OnChangeKeyfileOrPassword(bool? value)
        {
            _ = InvokeAsync(StateHasChanged);
        }
        private void SaveUser()
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
                settingsRepository.AddUser(SelectedUser);
                InfoText = $"User {SelectedUser.Username} was created";
            }
            else
            {
                settingsRepository.UpdateUser(SelectedUser);
                InfoText = $"Settings for user {SelectedUser.Username} were updated";
            }
        }
    }

}

