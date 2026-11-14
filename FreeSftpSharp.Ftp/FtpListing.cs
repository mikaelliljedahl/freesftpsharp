using System.Globalization;
using System.Text;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Ftp;

/// <summary>The directory listings: LIST (the "ls -l" format that clients parse), NLST (names) and MLSD/MLST (RFC 3659).</summary>
internal static class FtpListing
{
    /// <summary>The facts of MLSD and MLST, also in the FEAT reply.</summary>
    public const string MlstFacts = "type*;size*;modify*;";

    /// <summary>One "ls -l" line: "-rw-r--r-- 1 ftp ftp 1234 Nov 14 12:00 name". Times older than six months show the year.</summary>
    public static string ListLine(FileSystemEntry entry, DateTime nowUtc)
    {
        var type = entry.Type switch { FileSystemEntryType.Directory => 'd', FileSystemEntryType.Symlink => 'l', _ => '-' };
        var mode = entry.Permissions ?? (entry.IsDirectory ? 0x1EDu : 0x1A4u); // 0755, 0644
        var time = entry.LastWriteTimeUtc;
        var month = CultureInfo.InvariantCulture.DateTimeFormat.GetAbbreviatedMonthName(time.Month);
        var recent = time > nowUtc.AddDays(-180) && time <= nowUtc.AddDays(1);
        var when = recent
            ? string.Create(CultureInfo.InvariantCulture, $"{month} {time.Day,2} {time:HH:mm}")
            : string.Create(CultureInfo.InvariantCulture, $"{month} {time.Day,2}  {time.Year}");
        return string.Create(CultureInfo.InvariantCulture, $"{type}{Mode(mode)} 1 ftp ftp {entry.Size,12} {when} {entry.Name}");
    }

    /// <summary>One MLSD line, or the fact part of MLST: "type=file;size=3;modify=20261114120000; name".</summary>
    public static string Facts(FileSystemEntry entry, string name)
    {
        var type = entry.IsDirectory ? "dir" : "file";
        var size = entry.IsDirectory ? "" : string.Create(CultureInfo.InvariantCulture, $"size={entry.Size};");
        return $"type={type};{size}modify={Timestamp(entry.LastWriteTimeUtc)}; {name}";
    }

    /// <summary>The time format of MDTM and the modify fact: YYYYMMDDHHMMSS, UTC.</summary>
    public static string Timestamp(DateTime utc) => utc.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);

    /// <summary>The text of a listing on the data connection: one line per entry, CRLF.</summary>
    public static byte[] Text(IEnumerable<string> lines)
    {
        var builder = new StringBuilder();
        foreach (var line in lines)
            builder.Append(line).Append("\r\n");
        return Encoding.UTF8.GetBytes(builder.ToString());
    }

    private static string Mode(uint mode)
    {
        Span<char> chars = stackalloc char[9];
        const string letters = "rwxrwxrwx";
        for (var i = 0; i < 9; i++)
            chars[i] = (mode & (1u << (8 - i))) != 0 ? letters[i] : '-';
        return new string(chars);
    }

    /// <summary>
    /// The path argument of LIST and NLST without the "ls" options that many clients send ("-la", "-a /dir"). A name that
    /// starts with "-" cannot be listed this way; the client can use MLSD.
    /// </summary>
    public static string WithoutOptions(string argument)
    {
        var text = argument.TrimStart();
        while (text.StartsWith('-'))
        {
            var space = text.IndexOf(' ');
            text = space < 0 ? "" : text[(space + 1)..].TrimStart();
        }
        return text;
    }
}

/// <summary>The reply codes of the storage errors (RFC 959 section 4.2).</summary>
internal static class FtpErrors
{
    public static (int Code, string Text) Of(FileSystemException ex)
    {
        var (code, text) = ex.Error switch
        {
            FileSystemError.NoSuchFile => (550, "No such file or directory."),
            FileSystemError.PermissionDenied => (550, "Permission denied."),
            FileSystemError.NotADirectory => (550, "Not a directory."),
            FileSystemError.IsADirectory => (550, "Is a directory."),
            FileSystemError.DirectoryNotEmpty => (550, "Directory not empty."),
            FileSystemError.AlreadyExists => (550, "File exists."),
            FileSystemError.OpNotSupported => (504, "Not supported by this storage."),
            FileSystemError.QuotaExceeded => (552, "Quota exceeded."),
            FileSystemError.InvalidPath => (553, "File name not allowed."),
            _ => (451, "Local error in processing."),
        };
        if (!string.IsNullOrWhiteSpace(ex.ClientMessage))
            text += " " + ex.ClientMessage.ReplaceLineEndings(" ");
        return (code, text);
    }
}
