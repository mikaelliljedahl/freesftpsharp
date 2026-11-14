using System.Security.Cryptography;
using System.Text;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Infrastructure;

/// <summary>Builds the storage core for tests: registry, codec with <see cref="TestSecretProtector"/>, resolver and factory.</summary>
public static class TestStorage
{
    public static StorageOptionsCodec Codec(params IStorageProvider[] providers)
        => new(new StorageProviderRegistry(providers), new TestSecretProtector());

    /// <summary>The factory of the hosts over <paramref name="providers"/>; <paramref name="resolver"/> gets the codec of the factory.</summary>
    public static StorageFileSystemFactory Factory(IEnumerable<IStorageProvider> providers, Func<StorageOptionsCodec, IUserStorageResolver> resolver,
        IConnectionRegistry? connections = null, IEventBus? events = null)
    {
        var registry = new StorageProviderRegistry(providers);
        var codec = new StorageOptionsCodec(registry, new TestSecretProtector());
        return new StorageFileSystemFactory(registry, resolver(codec), codec, new EffectivePermissionsService(), connections, events);
    }

    /// <summary>A resolver that gives every user the same storage of "/" and no virtual folders.</summary>
    public static IUserStorageResolver Fixed(StorageOptionsCodec codec, string provider, object options)
        => new FixedResolver(new UserStorage(codec.Encode(provider, options), []));

    /// <summary>A resolver that gives every user this storage.</summary>
    public static IUserStorageResolver Fixed(UserStorage storage) => new FixedResolver(storage);

    private sealed class FixedResolver(UserStorage storage) : IUserStorageResolver
    {
        public UserStorage Resolve(User user) => storage;
    }
}

/// <summary>
/// A reversible <see cref="ISecretProtector"/> for tests: "test-protected:" and the base64 of the reversed text, so a
/// test can see that a stored secret is not in clear text. Anything else cannot be unprotected.
/// </summary>
public sealed class TestSecretProtector : ISecretProtector
{
    public const string Prefix = "test-protected:";

    public string Protect(string plaintext) => Prefix + Convert.ToBase64String(Encoding.UTF8.GetBytes(new string(plaintext.Reverse().ToArray())));

    public string Unprotect(string protectedValue)
    {
        if (!protectedValue.StartsWith(Prefix, StringComparison.Ordinal))
            throw new CryptographicException("Not protected by the test protector.");
        return new string(Encoding.UTF8.GetString(Convert.FromBase64String(protectedValue[Prefix.Length..])).Reverse().ToArray());
    }
}
