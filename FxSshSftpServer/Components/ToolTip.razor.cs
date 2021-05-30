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
    // https://chrissainty.com/building-a-simple-tooltip-component-for-blazor-in-under-10-lines-of-code/
    public partial class ToolTip : ComponentBase
    {

    [Parameter] public RenderFragment ChildContent { get; set; }
        [Parameter] public string Text { get; set; }
    }

}
