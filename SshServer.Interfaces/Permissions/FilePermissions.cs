namespace SshServer.Interfaces.Permissions;

/// <summary>
/// What a user may do in a virtual directory (<see cref="User.Permissions"/>). The permissions of a directory apply to
/// the entries in it and to every directory below it, until a more specific path has its own permissions.
/// </summary>
[Flags]
public enum FilePermissions
{
    /// <summary>Nothing is allowed.</summary>
    None = 0,

    /// <summary>List the directory and read the attributes (stat) of its entries.</summary>
    List = 1 << 0,

    /// <summary>Open a file for reading.</summary>
    Download = 1 << 1,

    /// <summary>Create a new file.</summary>
    Upload = 1 << 2,

    /// <summary>Write to an existing file (overwrite, truncate, append, resume), or replace it by a rename.</summary>
    Overwrite = 1 << 3,

    /// <summary>Remove a file or an empty directory.</summary>
    Delete = 1 << 4,

    /// <summary>Rename or move a file or directory (needed in the source and in the target directory).</summary>
    Rename = 1 << 5,

    /// <summary>Create a directory.</summary>
    CreateDirectories = 1 << 6,

    /// <summary>Create a symbolic link (no protocol creates links yet).</summary>
    CreateSymlinks = 1 << 7,

    /// <summary>Change the POSIX permission bits (chmod).</summary>
    ChangeMode = 1 << 8,

    /// <summary>Change the access and write times.</summary>
    ChangeTimes = 1 << 9,

    /// <summary>Everything. The default of "/" for every user.</summary>
    All = List | Download | Upload | Overwrite | Delete | Rename | CreateDirectories | CreateSymlinks | ChangeMode | ChangeTimes,
}
