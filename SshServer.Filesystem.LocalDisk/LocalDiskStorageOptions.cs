namespace SshServer.Filesystem.LocalDisk;

/// <summary>The options of the local disk storage.</summary>
/// <param name="RootDirectory">The directory on the local disk that is "/" for the user. A relative path is relative to the working directory.</param>
public sealed record LocalDiskStorageOptions(string RootDirectory);
