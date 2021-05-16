using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FxSshSftpServer.SftpService
{


    public enum FileServerProtocol
    {
        Sftp = 1,
        Scp = 2,
        Shell = 3,
        Tunneling = 4,
    }

    public enum FileServerAction
    {
        OpenDirectory = 1,
        CreateDirectory = 2,
        DeleteDirectory = 3,
        OpenFile = 4,
        DeleteFile = 5,
        GetItemInfo = 6,
        SetItemInfo = 7,
    }

    [Flags]
    public enum FileSystemOperation : long
    {
        /// <summary>
        /// Open file for reading. Get flags for file / directory.
        /// </summary>
        Read = 1,
        /// <summary>
        /// Open file for writing. Set flags for file / directory.
        /// </summary>
        Write = 2,
        /// <summary>Create file or directory.</summary>
        Create = 4,
        /// <summary>Delete file or directory.</summary>
        Delete = 8,
        /// <summary>List content of directory.</summary>
        List = 16, // 0x0000000000000010
        /// <summary>All operations.</summary>
        All = 2047, // 0x00000000000007FF
    }

    ///// <summary>
    //   /// Occurs after a file (or a part of a file) has been downloaded.
    //   /// </summary>
    //   public event EventHandler<FileTransferredEventArgs> FileDownloaded;

    //   /// <summary>
    //   /// Occurs after a file (or a part of a file) has been uploaded.
    //   /// </summary>
    //   public event EventHandler<FileTransferredEventArgs> FileUploaded;

    //   /// <summary>Occurs when path access authorization is required.</summary>
    //   public event EventHandler<PathAccessAuthorizationEventArgs> PathAccessAuthorization;

    //   /// <summary>Occurs when a shell command is executed.</summary>
    //   public event EventHandler<ShellCommandEventArgs> ShellCommand;

    //   /// <summary>Occurs when a tunnel is requested.</summary>
    //   public event EventHandler<TunnelRequestedEventArgs> TunnelRequested;
    // }
}
