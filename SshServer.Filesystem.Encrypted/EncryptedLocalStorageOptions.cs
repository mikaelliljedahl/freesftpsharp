using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace SshServer.Filesystem.Encrypted;

/// <summary>The options of the encrypted local disk storage.</summary>
/// <param name="RootDirectory">The directory on the local disk that is "/" for the user. A relative path is relative to the working directory.</param>
[DisplayName("Local disk (encrypted)")]
[Description("A directory on the disk of the server; the file contents are encrypted with the keys of Storage:Encryption. Use a new, empty directory.")]
public sealed record EncryptedLocalStorageOptions(
    [property: Display(Name = "Directory", Description = "A directory on the server. It is / for the client, who cannot leave it.", Prompt = "/srv/sftp/encrypted")]
    string RootDirectory);
