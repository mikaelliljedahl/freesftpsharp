using FxSsh.SshServerModule.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace FreeSftpSharp.WebDav;

// TEMPORARY probe for #126, removed before merge.
internal static class CodeQlProbe
{
    public static void Raw(HttpContext context, ILogger logger) =>
        logger.LogWarning("probe raw {Path}", context.Request.Path.Value);

    public static void Cleaned(HttpContext context, ILogger logger) =>
        logger.LogWarning("probe cleaned {Path}", LogText.Clean(context.Request.Path.Value));
}
