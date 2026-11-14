using System.Globalization;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Ftp;

/// <summary>The file and directory commands that do not need a data connection.</summary>
internal sealed partial class FtpSession
{
    private async Task CwdAsync(string path)
    {
        var entry = await FileSystem.StatAsync(path, true, Ct);
        if (entry == null)
            await ReplyAsync(550, "No such directory.");
        else if (!entry.IsDirectory)
            await ReplyAsync(550, "Not a directory.");
        else
        {
            _cwd = path;
            await ReplyAsync(250, "Directory changed to " + path + ".");
        }
    }

    private async Task MkdAsync(string path)
    {
        await FileSystem.CreateDirectoryAsync(path, Ct);
        await ReplyAsync(257, FtpReply.QuotePath(path) + " created.");
    }

    private async Task RnfrAsync(string path)
    {
        if (await FileSystem.StatAsync(path, false, Ct) == null)
        {
            await ReplyAsync(550, "No such file or directory.");
            return;
        }
        _renameFrom = path;
        await ReplyAsync(350, "Ready for RNTO.");
    }

    private async Task RntoAsync(string path)
    {
        var from = _renameFrom;
        _renameFrom = null;
        if (from == null)
        {
            await ReplyAsync(503, "Send RNFR first.");
            return;
        }
        await FileSystem.RenameAsync(from, path, RenameFlags.None, Ct);
        await ReplyAsync(250, "Renamed.");
    }

    private async Task SizeAsync(string path)
    {
        var entry = await FileSystem.StatAsync(path, true, Ct);
        if (entry is not { Type: FileSystemEntryType.File })
            await ReplyAsync(550, entry == null ? "No such file." : "Not a plain file.");
        else
            await ReplyAsync(213, entry.Size.ToString(CultureInfo.InvariantCulture));
    }

    private async Task MdtmAsync(string path)
    {
        var entry = await FileSystem.StatAsync(path, true, Ct);
        if (entry == null)
            await ReplyAsync(550, "No such file.");
        else
            await ReplyAsync(213, FtpListing.Timestamp(entry.LastWriteTimeUtc));
    }

    private async Task RestAsync(string argument)
    {
        if (!long.TryParse(argument.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var offset))
        {
            await ReplyAsync(501, "REST needs a byte offset.");
            return;
        }
        _restart = offset;
        await ReplyAsync(350, $"Restarting at {offset.ToString(CultureInfo.InvariantCulture)}. Send RETR or STOR.");
    }

    /// <summary>SITE CHMOD mode path (the only SITE command), through the storage (needs <see cref="StorageCapabilities.SetPermissions"/>).</summary>
    private async Task SiteAsync(string argument)
    {
        var parts = argument.Trim().Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length > 0 && parts[0].Equals("HELP", StringComparison.OrdinalIgnoreCase))
        {
            await ReplyAsync(214, "SITE CHMOD <octal mode> <path>");
            return;
        }
        if (parts.Length != 3 || !parts[0].Equals("CHMOD", StringComparison.OrdinalIgnoreCase))
        {
            await ReplyAsync(504, "Only SITE CHMOD is supported.");
            return;
        }
        if (parts[1].Length is < 1 or > 4 || !parts[1].All(c => c is >= '0' and <= '7'))
        {
            await ReplyAsync(501, "The mode must be octal, for example 644.");
            return;
        }
        var mode = Convert.ToUInt32(parts[1], 8) & 0x1FF;
        await FileSystem.SetAttributesAsync(Resolve(parts[2]), new FileAttributesUpdate { Permissions = mode }, Ct);
        await ReplyAsync(200, "SITE CHMOD command successful.");
    }

    private async Task MlstAsync(string path)
    {
        var entry = await FileSystem.StatAsync(path, true, Ct);
        if (entry == null)
        {
            await ReplyAsync(550, "No such file or directory.");
            return;
        }
        // The fact line starts with a space (RFC 3659 section 7.2); FtpReply adds it to the middle lines.
        await ReplyAsync(250, "Listing " + path + "\n" + FtpListing.Facts(entry, path) + "\nEnd.");
    }
}
