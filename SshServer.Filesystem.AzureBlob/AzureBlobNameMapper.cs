using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.AzureBlob;

/// <summary>
/// Maps the normalized virtual paths of one user to blob names below the name prefix. A file "/a/b.txt" is the blob
/// "prefix/a/b.txt"; a directory "/a" is the name prefix "prefix/a/", and its marker blob (so that an empty directory
/// exists) is the zero-length blob "prefix/a" with the metadata hdi_isfolder=true.
/// </summary>
internal sealed class AzureBlobNameMapper
{
    /// <summary>The longest blob name of Azure, in characters.</summary>
    public const int MaxNameLength = 1024;

    /// <summary>The most path segments (separated by "/") of a blob name.</summary>
    public const int MaxSegments = 254;

    public AzureBlobNameMapper(string? keyPrefix)
    {
        Prefix = NormalizePrefix(keyPrefix);
    }

    /// <summary>The name prefix of the user root: "" or "a/b/".</summary>
    public string Prefix { get; }

    /// <summary>"/users//alice/" and "users/alice" give "users/alice/"; empty gives "".</summary>
    public static string NormalizePrefix(string? keyPrefix)
    {
        var normalized = VirtualPath.Normalize(keyPrefix).TrimStart('/');
        return normalized.Length == 0 ? string.Empty : normalized + "/";
    }

    /// <summary>The blob name of the file at a normalized path other than the root.</summary>
    public string FileName(string normalizedPath) => BlobName(normalizedPath);

    /// <summary>
    /// The name of the marker blob of the directory at a normalized path other than the root: the name of the directory
    /// without a trailing slash, as Storage Explorer and Data Lake write it (the SDK removes a trailing slash from a blob
    /// name), with the metadata hdi_isfolder=true.
    /// </summary>
    public string MarkerName(string normalizedPath) => BlobName(normalizedPath);

    private string BlobName(string normalizedPath)
    {
        var name = Prefix + normalizedPath.Substring(1);
        // Azure removes a trailing dot from a blob name, so such a file could not be read back.
        if (name.EndsWith('.'))
            throw new FileSystemException(FileSystemError.InvalidPath, $"The storage does not accept a file name that ends with a dot: {normalizedPath}");
        return Check(name, normalizedPath);
    }

    /// <summary>The name prefix of the directory at a normalized path.</summary>
    public string DirectoryPrefix(string normalizedPath)
        => normalizedPath == VirtualPath.Root ? Prefix : Check(Prefix + normalizedPath.Substring(1) + "/", normalizedPath);

    /// <summary>
    /// The name of a listed blob or blob prefix (ending with "/") below <paramref name="directoryPrefix"/>, or null when
    /// no virtual path reaches it: an empty segment ("a//b"), ".", ".." or a name with "\" (a separator of the virtual paths).
    /// </summary>
    public static string? ChildName(string directoryPrefix, string blobOrPrefix)
    {
        if (!blobOrPrefix.StartsWith(directoryPrefix, StringComparison.Ordinal))
            return null;
        var name = blobOrPrefix.Substring(directoryPrefix.Length);
        if (name.EndsWith('/'))
            name = name.Substring(0, name.Length - 1);
        if (name.Length == 0 || name == "." || name == ".." || name.Contains('/') || name.Contains('\\'))
            return null;
        return name;
    }

    private static string Check(string name, string path)
    {
        if (name.Length > MaxNameLength || name.Count(c => c == '/') + 1 > MaxSegments)
            throw new FileSystemException(FileSystemError.InvalidPath, $"The path is too long for the storage: {path}");
        return name;
    }
}
