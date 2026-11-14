using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace SshServer.Filesystem.LocalDisk;

/// <summary>The options of the local disk storage.</summary>
/// <param name="RootDirectory">The directory on the local disk that is "/" for the user. A relative path is relative to the working directory.</param>
[DisplayName("Local disk")]
[Description("A directory on the disk of the server.")]
public sealed record LocalDiskStorageOptions(
    [property: Display(Name = "Directory", Description = "A directory on the server. It is / for the client, who cannot leave it.", Prompt = "/srv/sftp/shared")]
    string RootDirectory);
