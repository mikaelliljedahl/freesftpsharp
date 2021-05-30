using FxSsh.SshServerModule;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.JSInterop;
using Radzen;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace FxSshSftpServer.Components
{

    public static class FileDownload
    {

        public static async Task SaveFile(this IJSRuntime JSRuntime, byte[] file, string fileName)
        {
            string contentType = "application/octet-stream";

            // Check if the IJSRuntime is the WebAssembly implementation of the JSRuntime
            
                // Fall back to the slow method if not in WebAssembly
            await JSRuntime.InvokeVoidAsync("BlazorDownloadFile", fileName, contentType, file);
           
        }
    }
}

