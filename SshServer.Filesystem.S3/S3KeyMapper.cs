using System.Text;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.S3;

/// <summary>
/// Maps the normalized virtual paths of one user to object keys below the key prefix. A file "/a/b.txt" is the object
/// "prefix/a/b.txt"; a directory "/a" is the key prefix "prefix/a/", and its marker object (so that an empty directory
/// exists) is the zero-byte object with that key.
/// </summary>
internal sealed class S3KeyMapper
{
    /// <summary>The longest object key of S3, in UTF-8 bytes.</summary>
    public const int MaxKeyBytes = 1024;

    public S3KeyMapper(string? keyPrefix)
    {
        Prefix = NormalizePrefix(keyPrefix);
    }

    /// <summary>The key prefix of the user root: "" or "a/b/".</summary>
    public string Prefix { get; }

    /// <summary>"/users//alice/" and "users/alice" give "users/alice/"; empty gives "".</summary>
    public static string NormalizePrefix(string? keyPrefix)
    {
        var normalized = VirtualPath.Normalize(keyPrefix).TrimStart('/');
        return normalized.Length == 0 ? string.Empty : normalized + "/";
    }

    /// <summary>The key of the file at a normalized path other than the root.</summary>
    public string FileKey(string normalizedPath) => Check(Prefix + normalizedPath.Substring(1), normalizedPath);

    /// <summary>The key prefix of the directory at a normalized path; also the key of its marker object.</summary>
    public string DirectoryPrefix(string normalizedPath)
        => normalizedPath == VirtualPath.Root ? Prefix : Check(Prefix + normalizedPath.Substring(1) + "/", normalizedPath);

    /// <summary>
    /// The name of a listed object key or common prefix (ending with "/") below <paramref name="directoryPrefix"/>, or
    /// null when no virtual path reaches it: the marker of the directory itself, an empty segment ("a//b"), ".", ".."
    /// or a name with "\" (a separator of the virtual paths).
    /// </summary>
    public static string? ChildName(string directoryPrefix, string keyOrPrefix)
    {
        if (!keyOrPrefix.StartsWith(directoryPrefix, StringComparison.Ordinal))
            return null;
        var name = keyOrPrefix.Substring(directoryPrefix.Length);
        if (name.EndsWith('/'))
            name = name.Substring(0, name.Length - 1);
        if (name.Length == 0 || name == "." || name == ".." || name.Contains('/') || name.Contains('\\'))
            return null;
        return name;
    }

    private static string Check(string key, string path)
    {
        if (Encoding.UTF8.GetByteCount(key) > MaxKeyBytes)
            throw new FileSystemException(FileSystemError.InvalidPath, $"The path is too long for the storage: {path}");
        return key;
    }
}
