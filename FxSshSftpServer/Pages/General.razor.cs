using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace FxSshSftpServer.Pages
{
   
    public partial class General : ComponentBase
    {


        private int currentCount = 0;

        private void IncrementCount()
        {
            currentCount++;
        }


        
    }

}

