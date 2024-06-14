using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SshServerModule.Services;

internal class Permissions
{
#pragma warning disable IDE1006 // Naming Styles
#pragma warning disable SA1310 // Field names should not contain underscore
    internal const uint S_IFMT = 0xF000; // bitmask for the file type bitfields
    internal const uint S_IFSOCK = 0xC000; // socket
    internal const uint S_IFLNK = 0xA000; // symbolic link
    internal const uint S_IFREG = 0x8000; // regular file
    internal const uint S_IFBLK = 0x6000; // block device
    internal const uint S_IFDIR = 0x4000; // directory
    internal const uint S_IFCHR = 0x2000; // character device
    internal const uint S_IFIFO = 0x1000; // FIFO
    internal const uint S_ISUID = 0x0800; // set UID bit
    internal const uint S_ISGID = 0x0400; // set-group-ID bit (see below)
    internal const uint S_ISVTX = 0x0200; // sticky bit (see below)
    internal const uint S_IRUSR = 0x0100; // owner has read permission
    internal const uint S_IWUSR = 0x0080; // owner has write permission
    internal const uint S_IXUSR = 0x0040; // owner has execute permission
    internal const uint S_IRGRP = 0x0020; // group has read permission
    internal const uint S_IWGRP = 0x0010; // group has write permission
    internal const uint S_IXGRP = 0x0008; // group has execute permission
    internal const uint S_IROTH = 0x0004; // others have read permission
    internal const uint S_IWOTH = 0x0002; // others have write permission
    internal const uint S_IXOTH = 0x0001; // others have execute permission
#pragma warning restore SA1310 // Field names should not contain underscore
#pragma warning restore IDE1006 // Naming Styles

    public Permissions(short mode, bool isDirectory)
    {

        if (mode is < 0 or > 999)
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }

        var modeBytes = mode.ToString(CultureInfo.InvariantCulture).PadLeft(3, '0').ToCharArray();

        var permission = ((modeBytes[0] & 0x0F) * 8 * 8) + ((modeBytes[1] & 0x0F) * 8) + (modeBytes[2] & 0x0F);

        OwnerCanRead = (permission & S_IRUSR) == S_IRUSR;
        OwnerCanWrite = (permission & S_IWUSR) == S_IWUSR;
        OwnerCanExecute = (permission & S_IXUSR) == S_IXUSR;

        GroupCanRead = (permission & S_IRGRP) == S_IRGRP;
        GroupCanWrite = (permission & S_IWGRP) == S_IWGRP;
        GroupCanExecute = (permission & S_IXGRP) == S_IXGRP;

        OthersCanRead = (permission & S_IROTH) == S_IROTH;
        OthersCanWrite = (permission & S_IWOTH) == S_IWOTH;
        OthersCanExecute = (permission & S_IXOTH) == S_IXOTH;


        if (isDirectory)
        {
            IsRegularFile = false;
            IsDirectory = true;
        }
        else
        {
            IsRegularFile = true;
            IsDirectory = false;
        }
    }


    internal uint PermissionsAsUint
    {
        get
        {
            uint permission = 0;

            if (IsRegularFile)
            {
                permission |= S_IFREG;
            }
            if (IsDirectory)
            {
                permission |= S_IFDIR;
            }
            if (OwnerCanRead)
            {
                permission |= S_IRUSR;
            }
            if (OwnerCanWrite)
            {
                permission |= S_IWUSR;
            }
            if (OwnerCanExecute)
            {
                permission |= S_IXUSR;
            }
            if (GroupCanRead)
            {
                permission |= S_IRGRP;
            }
            if (GroupCanWrite)
            {
                permission |= S_IWGRP;
            }
            if (GroupCanExecute)
            {
                permission |= S_IXGRP;
            }
            if (OthersCanRead)
            {
                permission |= S_IROTH;
            }
            if (OthersCanWrite)
            {
                permission |= S_IWOTH;
            }
            if (OthersCanExecute)
            {
                permission |= S_IXOTH;
            }
            return permission;
        }
    }


    public bool OwnerCanRead { get; set; }
    public bool OwnerCanWrite { get; set; }
    public bool OwnerCanExecute { get; set; }
    public bool GroupCanRead { get; set; }
    public bool GroupCanWrite { get; set; }
    public bool GroupCanExecute { get; set; }
    public bool OthersCanRead { get; set; }
    public bool OthersCanWrite { get; set; }
    public bool OthersCanExecute { get; set; }
    public bool IsRegularFile { get; set; }
    public bool IsDirectory { get; set; }
}
