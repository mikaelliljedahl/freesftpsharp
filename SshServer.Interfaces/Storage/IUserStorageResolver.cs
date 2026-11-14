namespace SshServer.Interfaces.Storage;

/// <summary>The storage of a user: the provider name and the options for <see cref="IStorageProvider.CreateAsync"/>.</summary>
/// <param name="Provider">The <see cref="IStorageProvider.Name"/>.</param>
/// <param name="Options">The options, of the <see cref="IStorageProvider.OptionsType"/> of the provider.</param>
public sealed record StorageSelection(string Provider, object Options);

/// <summary>
/// Gives the storage of a user. Today every user has the local disk at <see cref="User.UserRootDirectory"/>
/// (registered by <c>AddLocalDiskStorage</c>); the per-user storage configuration (#56) replaces this.
/// </summary>
public interface IUserStorageResolver
{
    StorageSelection Resolve(User user);
}
