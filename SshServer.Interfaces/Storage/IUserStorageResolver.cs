namespace SshServer.Interfaces.Storage;

/// <summary>A storage location mounted at a virtual path of a user (a <see cref="VirtualFolder"/>).</summary>
/// <param name="Path">The normalized virtual path, for example "/shared".</param>
/// <param name="Name">The name of the virtual folder, for the messages.</param>
/// <param name="Storage">The storage of the folder.</param>
/// <param name="FolderId">The <see cref="VirtualFolder.Id"/>, for example for its quota usage.</param>
public sealed record StorageMount(string Path, string Name, StorageConfig Storage, int FolderId);

/// <summary>The storage of a user: the storage of "/" and the virtual folders mounted below it.</summary>
public sealed record UserStorage(StorageConfig Root, IReadOnlyList<StorageMount> Mounts);

/// <summary>
/// Gives the storage of a user: <see cref="User.Storage"/>, or the <see cref="IDefaultUserStorage"/> for a user without
/// one, and the mounted <see cref="User.VirtualFolders"/>.
/// </summary>
public interface IUserStorageResolver
{
    /// <summary>Throws <see cref="ArgumentException"/> when a mounted virtual folder does not exist.</summary>
    UserStorage Resolve(User user);
}

/// <summary>
/// The storage of a user without a storage configuration (<see cref="User.Storage"/> null): the local disk at
/// <see cref="User.UserRootDirectory"/> (registered by <c>AddLocalDiskStorage</c>), so a server without any storage
/// configuration works as before.
/// </summary>
public interface IDefaultUserStorage
{
    StorageConfig For(User user);
}
