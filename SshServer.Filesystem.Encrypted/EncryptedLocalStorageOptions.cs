namespace SshServer.Filesystem.Encrypted;

/// <summary>The options of the encrypted local disk storage.</summary>
/// <param name="RootDirectory">The directory on the local disk that is "/" for the user. A relative path is relative to the working directory.</param>
public sealed record EncryptedLocalStorageOptions(string RootDirectory);
