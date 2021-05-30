using FxSsh.SshServerModule;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Radzen;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace FxSshSftpServer.Components
{

    public partial class TwoColumnRow : ComponentBase
    {

        

        [Parameter]
        public RenderFragment ChildContent { get; set; }

        [Parameter]
        public string TooltipText { get; set; }

        [Parameter]
        public string HeaderText { get; set; }

    }
}
