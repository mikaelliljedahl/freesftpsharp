using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SshServerModule.Services;

/// <summary>
/// Contains SFTP file attributes.
/// </summary>
public class SftpFileAttributes
{


    private readonly DateTime _originalLastAccessTimeUtc;
    private readonly DateTime _originalLastWriteTimeUtc;
    private readonly long _originalSize;
    private readonly int _originalUserId;
    private readonly int _originalGroupId;
    private readonly Permissions _originalPermissions;
    private readonly IDictionary<string, string> _originalExtensions;

    private bool _isBitFiledsBitSet;
    private bool _isUIDBitSet;
    private bool _isGroupIDBitSet;
    private bool _isStickyBitSet;

    internal bool IsLastAccessTimeChanged
    {
        get { return _originalLastAccessTimeUtc != LastAccessTimeUtc; }
    }

    internal bool IsLastWriteTimeChanged
    {
        get { return _originalLastWriteTimeUtc != LastWriteTimeUtc; }
    }

    internal bool IsSizeChanged
    {
        get { return _originalSize != Size; }
    }

    internal bool IsUserIdChanged
    {
        get { return _originalUserId != UserId; }
    }

    internal bool IsGroupIdChanged
    {
        get { return _originalGroupId != GroupId; }
    }

    internal bool IsPermissionsChanged
    {
        get { return _originalPermissions != Permissions; }
    }

    internal bool IsExtensionsChanged
    {
        get { return _originalExtensions != null && Extensions != null && !_originalExtensions.SequenceEqual(Extensions); }
    }

    /// <summary>
    /// Gets or sets the UTC time the current file or directory was last accessed.
    /// </summary>
    /// <value>
    /// The UTC time that the current file or directory was last accessed.
    /// </value>
    public DateTime LastAccessTimeUtc { get; set; }

    /// <summary>
    /// Gets or sets the UTC time when the current file or directory was last written to.
    /// </summary>
    /// <value>
    /// The UTC time the current file was last written.
    /// </value>
    public DateTime LastWriteTimeUtc { get; set; }

    /// <summary>
    /// Gets or sets the size, in bytes, of the current file.
    /// </summary>
    /// <value>
    /// The size of the current file in bytes.
    /// </value>
    public long Size { get; set; }

    /// <summary>
    /// Gets or sets file user id.
    /// </summary>
    /// <value>
    /// File user id.
    /// </value>
    public int UserId { get; set; }

    /// <summary>
    /// Gets or sets file group id.
    /// </summary>
    /// <value>
    /// File group id.
    /// </value>
    public int GroupId { get; set; }
    internal Permissions Permissions { get; set; }

    /// <summary>
    /// Gets a value indicating whether file represents a socket.
    /// </summary>
    /// <value>
    /// <see langword="true"/> if file represents a socket; otherwise, <see langword="false"/>.
    /// </value>
    public bool IsSocket { get; private set; }

    /// <summary>
    /// Gets a value indicating whether file represents a symbolic link.
    /// </summary>
    /// <value>
    /// <see langword="true"/> if file represents a symbolic link; otherwise, <see langword="false"/>.
    /// </value>
    public bool IsSymbolicLink { get; private set; }

    /// <summary>
    /// Gets a value indicating whether file represents a regular file.
    /// </summary>
    /// <value>
    /// <see langword="true"/> if file represents a regular file; otherwise, <see langword="false"/>.
    /// </value>
    public bool IsRegularFile { get; private set; }

    /// <summary>
    /// Gets a value indicating whether file represents a block device.
    /// </summary>
    /// <value>
    /// <see langword="true"/> if file represents a block device; otherwise, <see langword="false"/>.
    /// </value>
    public bool IsBlockDevice { get; private set; }

    /// <summary>
    /// Gets a value indicating whether file represents a directory.
    /// </summary>
    /// <value>
    /// <see langword="true"/> if file represents a directory; otherwise, <see langword="false"/>.
    /// </value>
    public bool IsDirectory { get; private set; }

    /// <summary>
    /// Gets a value indicating whether file represents a character device.
    /// </summary>
    /// <value>
    /// <see langword="true"/> if file represents a character device; otherwise, <see langword="false"/>.
    /// </value>
    public bool IsCharacterDevice { get; private set; }

    /// <summary>
    /// Gets a value indicating whether file represents a named pipe.
    /// </summary>
    /// <value>
    /// <see langword="true"/> if file represents a named pipe; otherwise, <see langword="false"/>.
    /// </value>
    public bool IsNamedPipe { get; private set; }



    /// <summary>
    /// Gets the extensions.
    /// </summary>
    /// <value>
    /// The extensions.
    /// </value>
    public IDictionary<string, string> Extensions { get; private set; }

    private SftpFileAttributes()
    {
    }

    internal SftpFileAttributes(DateTime lastAccessTimeUtc, DateTime lastWriteTimeUtc, long size, int userId, int groupId, bool isDirectory, IDictionary<string, string> extensions)
    {
        LastAccessTimeUtc = _originalLastAccessTimeUtc = lastAccessTimeUtc;
        LastWriteTimeUtc = _originalLastWriteTimeUtc = lastWriteTimeUtc;
        Size = _originalSize = size;
        UserId = _originalUserId = userId;
        GroupId = _originalGroupId = groupId;
        Permissions = _originalPermissions = new Permissions(666, isDirectory);
        Extensions = _originalExtensions = extensions;
    }

    ///// <summary>
    ///// Sets the permissions.
    ///// </summary>
    ///// <param name="mode">The mode.</param>
    //public void SetPermissions(short mode)
    //{
    //    if (mode is < 0 or > 999)
    //    {
    //        throw new ArgumentOutOfRangeException(nameof(mode));
    //    }

    //    var modeBytes = mode.ToString(CultureInfo.InvariantCulture).PadLeft(3, '0').ToCharArray();

    //    var permission = ((modeBytes[0] & 0x0F) * 8 * 8) + ((modeBytes[1] & 0x0F) * 8) + (modeBytes[2] & 0x0F);

    //    Permissions.OwnerCanRead = (permission & Permissions.S_IRUSR) == Permissions.S_IRUSR;
    //    Permissions.OwnerCanWrite = (permission & Permissions.S_IWUSR) == Permissions.S_IWUSR;
    //    Permissions.OwnerCanExecute = (permission & Permissions.S_IXUSR) == Permissions.S_IXUSR;

    //    Permissions.GroupCanRead = (permission & Permissions.S_IRGRP) == Permissions.S_IRGRP;
    //    Permissions.GroupCanWrite = (permission & Permissions.S_IWGRP) == Permissions.S_IWGRP;
    //    Permissions.GroupCanExecute = (permission & Permissions.S_IXGRP) == Permissions.S_IXGRP;

    //    Permissions.OthersCanRead = (permission & Permissions.S_IROTH) == Permissions.S_IROTH;
    //    Permissions.OthersCanWrite = (permission & Permissions.S_IWOTH) == Permissions.S_IWOTH;
    //    Permissions.OthersCanExecute = (permission & Permissions.S_IXOTH) == Permissions.S_IXOTH;
    //}

}
