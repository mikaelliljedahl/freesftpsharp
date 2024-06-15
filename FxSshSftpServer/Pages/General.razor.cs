using FxSsh.SshServerModule;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace FxSshSftpServer.Pages
{
   
    public partial class General : ComponentBase
    {
        [Inject]
        public ISettingsRepository settingsRepository { get; set; }
        public ServerSettings ServerSettings { get; private set; }
        public bool Savesuccess { get; private set; }

        protected override void OnAfterRender(bool firstRender)
        {
            if (firstRender)
            {
                ServerSettings = settingsRepository.ServerSettings;
                _ = InvokeAsync(StateHasChanged);
            }
        }

      
        private void OnSave()
        {
            Savesuccess = settingsRepository.UpdateServerSettings(ServerSettings);

            

        }



    }

}

