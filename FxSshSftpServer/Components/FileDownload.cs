using Microsoft.JSInterop;
using System.Threading.Tasks;

namespace FxSshSftpServer.Components
{
    public static class FileDownload
    {
        /// <summary>Lets the browser save <paramref name="file"/> (BlazorDownloadFile in wwwroot/js/site.js). False when the browser call failed.</summary>
        public static async Task<bool> SaveFile(this IJSRuntime jsRuntime, byte[] file, string fileName, string contentType = "application/octet-stream")
        {
            try
            {
                await jsRuntime.InvokeVoidAsync("BlazorDownloadFile", fileName, contentType, file);
                return true;
            }
            catch (JSException)
            {
                return false;
            }
        }
    }
}
