namespace SshServer.Interfaces.Storage;

/// <summary>
/// A storage backend (docs/ARCHITECTURE.md, "Storage backends"): one class per backend project, found by its
/// <see cref="Name"/> through <see cref="IStorageProviderRegistry"/>. Derive from <see cref="StorageProvider{TOptions}"/>.
/// </summary>
public interface IStorageProvider
{
    /// <summary>The unique name of the backend, for example "local" or "s3" (compared without case).</summary>
    string Name { get; }

    /// <summary>The type of the options record of the backend, for example to bind or deserialize stored options.</summary>
    Type OptionsType { get; }

    /// <summary>The problems of <paramref name="options"/>; empty when they are valid. Options of another type are invalid.</summary>
    IReadOnlyList<string> Validate(object options);

    /// <summary>
    /// Creates the file system of one storage location (for example one user root). Throws <see cref="ArgumentException"/>
    /// when the options are not valid (<see cref="Validate"/>).
    /// </summary>
    ValueTask<IFileSystem> CreateAsync(object options, CancellationToken ct);
}

/// <summary>The base class of a storage provider with one typed options record.</summary>
/// <typeparam name="TOptions">The options record of the backend.</typeparam>
public abstract class StorageProvider<TOptions> : IStorageProvider
    where TOptions : class
{
    public abstract string Name { get; }

    public Type OptionsType => typeof(TOptions);

    public IReadOnlyList<string> Validate(object options)
        => options is TOptions typed ? ValidateOptions(typed) : [$"The options of the storage provider '{Name}' must be a {typeof(TOptions).Name}."];

    public ValueTask<IFileSystem> CreateAsync(object options, CancellationToken ct)
    {
        var problems = Validate(options);
        if (problems.Count > 0)
            throw new ArgumentException($"Invalid options of the storage provider '{Name}': {string.Join(" ", problems)}", nameof(options));
        return CreateFileSystemAsync((TOptions)options, ct);
    }

    /// <summary>The problems of valid-typed options; empty when they are valid.</summary>
    protected abstract IReadOnlyList<string> ValidateOptions(TOptions options);

    /// <summary>Creates the file system from validated options.</summary>
    protected abstract ValueTask<IFileSystem> CreateFileSystemAsync(TOptions options, CancellationToken ct);
}
