using System;
using System.Globalization;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The <c>Content-Range</c> of one upload chunk (RFC 9110 section 14.4): "bytes first-last/total", with a known total.
    /// "bytes */0" is an empty file.
    /// </summary>
    public readonly record struct ContentRange(long First, long Last, long Total)
    {
        /// <summary>The number of bytes of the chunk (0 for an empty file).</summary>
        public long Length => Total == 0 ? 0 : Last - First + 1;

        public bool IsLastChunk => Total == 0 || Last == Total - 1;

        public static bool TryParse(string value, out ContentRange range)
        {
            range = default;
            if (string.IsNullOrWhiteSpace(value))
                return false;
            var text = value.Trim();
            if (!text.StartsWith("bytes ", StringComparison.OrdinalIgnoreCase))
                return false;
            text = text.Substring(6).Trim();
            var slash = text.IndexOf('/');
            if (slash < 0 || !TryParseNumber(text.AsSpan(slash + 1), out var total))
                return false;
            var span = text.AsSpan(0, slash);
            if (span.SequenceEqual("*"))
            {
                // Only an empty file has no byte range.
                if (total != 0)
                    return false;
                range = new ContentRange(0, -1, 0);
                return true;
            }
            var dash = span.IndexOf('-');
            if (dash <= 0 || !TryParseNumber(span[..dash], out var first) || !TryParseNumber(span[(dash + 1)..], out var last))
                return false;
            if (first > last || last >= total)
                return false;
            range = new ContentRange(first, last, total);
            return true;
        }

        private static bool TryParseNumber(ReadOnlySpan<char> text, out long number) =>
            long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out number) && number >= 0;
    }
}
