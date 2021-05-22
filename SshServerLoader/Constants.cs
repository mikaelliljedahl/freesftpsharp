using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FxSshSftpServer.SftpService
{
    // https://datatracker.ietf.org/doc/html/draft-ietf-secsh-connect-11#page-10
    // https://assets.ctfassets.net/0lvk5dbamxpi/6jBxT5LDgMqutNK4mPTGKd/4fa27cb4a130bca3b48a10c9045b0497/draft-ietf-secsh-filexfer-02

    public enum RequestPacketType
    {
        SSH_FXP_INIT = 1,
        SSH_FXP_VERSION = 2,
        SSH_FXP_OPEN = 3,
        SSH_FXP_CLOSE = 4,
        SSH_FXP_READ = 5,
        SSH_FXP_WRITE = 6,
        SSH_FXP_LSTAT = 7,
        SSH_FXP_FSTAT = 8,
        SSH_FXP_SETSTAT = 9,
        SSH_FXP_FSETSTAT = 10,
        SSH_FXP_OPENDIR = 11,
        SSH_FXP_READDIR = 12,
        SSH_FXP_REMOVE = 13,
        SSH_FXP_MKDIR = 14,
        SSH_FXP_RMDIR = 15,
        SSH_FXP_REALPATH = 16,
        SSH_FXP_STAT = 17,
        SSH_FXP_RENAME = 18,
        SSH_FXP_READLINK = 19,
        SSH_FXP_SYMLINK = 20,
        SSH_FXP_STATUS = 101,
        SSH_FXP_HANDLE = 102,
        SSH_FXP_DATA = 103,
        SSH_FXP_NAME = 104,
        SSH_FXP_ATTRS = 105,
        SSH_FXP_EXTENDED = 200,
        SSH_FXP_EXTENDED_REPLY = 201
    }

    //public enum SftpEvents
    //{
    //    REALPATH, STAT, LSTAT, FSTAT,
    //    OPENDIR, CLOSE, REMOVE, READDIR,
    //    OPEN, READ, WRITE, RENAME,
    //    MKDIR, RMDIR
    //}

    public enum FxpStatusType
    {
        SSH_FX_OK = 0,
        SSH_FX_EOF = 1,
        SSH_FX_NO_SUCH_FILE = 2,
        SSH_FX_PERMISSION_DENIED = 3,
        SSH_FX_FAILURE = 4,
        SSH_FX_BAD_MESSAGE = 5,
        SSH_FX_NO_CONNECTION = 6,
        SSH_FX_CONNECTION_LOST = 7,
        SSH_FX_OP_UNSUPPORTED = 8
    }

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
