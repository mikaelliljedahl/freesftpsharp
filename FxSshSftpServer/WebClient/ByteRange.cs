using System;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The part of a file that a download sends (RFC 9110 section 14): the whole file, or one range of a <c>Range</c>
    /// header, so a browser or download manager can resume. Several ranges are answered with the whole file (allowed by
    /// the RFC). An <c>If-Range</c> date that is not the last write time of the file gives the whole file.
    /// </summary>
    public readonly record struct ByteRange(long First, long Length, bool IsPartial, bool Unsatisfiable)
    {
        public long Last => First + Length - 1;

        public static ByteRange Select(StringValues rangeHeader, StringValues ifRangeHeader, DateTimeOffset lastModified, long size)
        {
            var whole = new ByteRange(0, size, false, false);
            if (StringValues.IsNullOrEmpty(rangeHeader) || rangeHeader.Count != 1)
                return whole;
            if (!StringValues.IsNullOrEmpty(ifRangeHeader))
            {
                // Only the date form: the downloads have no entity tag.
                if (!HeaderUtilities.TryParseDate(ifRangeHeader.ToString(), out var date)
                    || Math.Abs((date - lastModified).TotalSeconds) >= 1)
                    return whole;
            }
            if (!RangeHeaderValue.TryParse(rangeHeader.ToString(), out var parsed)
                || !string.Equals(parsed.Unit.Value, "bytes", StringComparison.OrdinalIgnoreCase)
                || parsed.Ranges.Count != 1)
                return whole;

            var item = System.Linq.Enumerable.First(parsed.Ranges);
            long first, last;
            if (item.From is { } from)
            {
                if (from >= size)
                    return new ByteRange(0, 0, false, true);
                first = from;
                last = item.To is { } to ? Math.Min(to, size - 1) : size - 1;
            }
            else if (item.To is { } suffix && suffix > 0)
            {
                if (size == 0)
                    return new ByteRange(0, 0, false, true);
                first = Math.Max(0, size - suffix);
                last = size - 1;
            }
            else
            {
                return new ByteRange(0, 0, false, true);
            }
            return new ByteRange(first, last - first + 1, true, false);
        }
    }
}
