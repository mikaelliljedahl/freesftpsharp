using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FxSsh.SshServerModule
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
        SSH_FXP_UNKNOWN = 100,
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

    public enum SftpStatusType
    {
        SSH_FX_OK = 0,
        SSH_FX_EOF = 1,
        SSH_FX_NO_SUCH_FILE = 2,
        SSH_FX_PERMISSION_DENIED = 3,
        SSH_FX_FAILURE = 4,
        SSH_FX_BAD_MESSAGE = 5,
        SSH_FX_NO_CONNECTION = 6,
        SSH_FX_CONNECTION_LOST = 7,
        SSH_FX_OP_UNSUPPORTED = 8, // version 3 - last one
        SSH_FX_INVALID_HANDLE = 9,
        SSH_FX_NO_SUCH_PATH = 10,
        SSH_FX_FILE_ALREADY_EXISTS = 11,
        SSH_FX_WRITE_PROTECT = 12,
        SSH_FX_NO_MEDIA = 13,
        SSH_FX_NO_SPACE_ON_FILESYSTEM = 14,
        SSH_FX_QUOTA_EXCEEDED = 15,
        SSH_FX_UNKNOWN_PRINCIPAL = 16,
        SSH_FX_LOCK_CONFLICT = 17,
        SSH_FX_DIR_NOT_EMPTY = 18,
        SSH_FX_NOT_A_DIRECTORY = 19,
        SSH_FX_INVALID_FILENAME = 20,
        SSH_FX_LINK_LOOP = 21,
        SSH_FX_CANNOT_DELETE = 22,
        SSH_FX_INVALID_PARAMETER = 23,
        SSH_FX_FILE_IS_A_DIRECTORY = 24,
        SSH_FX_BYTE_RANGE_LOCK_CONFLICT = 25,
        SSH_FX_BYTE_RANGE_LOCK_REFUSED = 26,
        SSH_FX_DELETE_PENDING = 27,
        SSH_FX_FILE_CORRUPT = 28,
        SSH_FX_OWNER_INVALID = 29,
        SSH_FX_GROUP_INVALID = 30,
        SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK = 31
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

    [Flags]
    public enum FileOrDirAttributeType : byte
    {
        SSH_FILEXFER_TYPE_REGULAR          = 1,
        SSH_FILEXFER_TYPE_DIRECTORY        = 2,
        SSH_FILEXFER_TYPE_SYMLINK          = 3,
        SSH_FILEXFER_TYPE_SPECIAL          = 4,
        SSH_FILEXFER_TYPE_UNKNOWN          = 5,
        SSH_FILEXFER_TYPE_SOCKET           = 6,
        SSH_FILEXFER_TYPE_CHAR_DEVICE      = 7,
        SSH_FILEXFER_TYPE_BLOCK_DEVICE     = 8,
        SSH_FILEXFER_TYPE_FIFO             = 9
    }

}
