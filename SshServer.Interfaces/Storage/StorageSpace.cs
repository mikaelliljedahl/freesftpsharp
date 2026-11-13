namespace SshServer.Interfaces.Storage;

/// <summary>The size and free space of a storage (<see cref="IFileSystem.GetStorageSpaceAsync"/>).</summary>
/// <param name="TotalBytes">The size of the storage.</param>
/// <param name="FreeBytes">The free space.</param>
/// <param name="AvailableBytes">The free space that this user can use.</param>
public sealed record StorageSpace(ulong TotalBytes, ulong FreeBytes, ulong AvailableBytes);
