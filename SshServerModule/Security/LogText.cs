#nullable enable
using System.Globalization;
using System.Text;

namespace FxSsh.SshServerModule.Security
{
    /// <summary>
    /// Makes a value from a client safe for one log line (log forging, CWE-117): a control character such as CR or LF
    /// becomes an escape ("\n", "\r", "\t" or "\u001b"), so a client cannot start a forged line. Use it for every value
    /// that the client chose: paths, user names, headers, lock tokens.
    /// </summary>
    public static class LogText
    {
        public static string? Clean(string? value)
        {
            if (value == null)
                return null;
            var index = 0;
            while (index < value.Length && !char.IsControl(value[index]))
                index++;
            if (index == value.Length)
                return value;

            var builder = new StringBuilder(value.Length + 8).Append(value, 0, index);
            for (; index < value.Length; index++)
            {
                var c = value[index];
                builder.Append(c switch
                {
                    '\n' => "\\n",
                    '\r' => "\\r",
                    '\t' => "\\t",
                    _ when char.IsControl(c) => "\\u" + ((int)c).ToString("x4", CultureInfo.InvariantCulture),
                    _ => c.ToString(),
                });
            }
            return builder.ToString();
        }
    }
}
