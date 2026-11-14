namespace SshServer.Interfaces.Storage;

/// <summary>Creates the file system of a user for a session.</summary>
public interface IFileSystemFactory
{
    /// <summary>
    /// The file system of <paramref name="user"/>, with "/" as the user root. Throws <see cref="ArgumentException"/> when
    /// the storage configuration of the user is not valid.
    /// </summary>
    ValueTask<IFileSystem> CreateAsync(User user, CancellationToken ct);
}
