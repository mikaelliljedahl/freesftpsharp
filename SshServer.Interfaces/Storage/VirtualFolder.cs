namespace SshServer.Interfaces.Storage;

/// <summary>
/// A virtual folder (issue #56): a named storage location that is mounted into the file system of one or more users
/// at a virtual path (<see cref="VirtualFolderMount"/>), for example a shared S3 prefix at <c>/incoming</c>.
/// </summary>
public sealed class VirtualFolder
{
    public int Id { get; set; }

    /// <summary>The unique name (compared without case), for example "shared-incoming".</summary>
    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    /// <summary>The storage of the folder.</summary>
    public StorageConfig Storage { get; set; } = new();
}

/// <summary>A <see cref="VirtualFolder"/> mounted into the file system of a user.</summary>
public sealed class VirtualFolderMount
{
    /// <summary>The <see cref="VirtualFolder.Id"/>.</summary>
    public int VirtualFolderId { get; set; }

    /// <summary>The normalized virtual path in the user's file system, for example "/shared"; never "/".</summary>
    public string MountPath { get; set; } = string.Empty;
}
