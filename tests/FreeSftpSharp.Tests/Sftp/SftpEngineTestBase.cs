using SshServer.Filesystem.LocalDisk;

namespace FreeSftpSharp.Tests.Sftp;

/// <summary>
/// A temporary directory with the user root (<c>root</c>, "/" for the client) and a secret file next to it
/// (<c>config.db</c>), and an <see cref="SftpEngineClient"/> on a <see cref="LocalFileSystem"/> for the root.
/// The client is initialized (INIT/VERSION) and <see cref="SftpEngineClient.Responses"/> is empty.
/// </summary>
public abstract class SftpEngineTestBase : IDisposable
{
    protected const string SecretContent = "secret settings";

    private protected SftpEngineTestBase()
    {
        TempDirectory = Path.Combine(Path.GetTempPath(), "freesftpsharp-tests", Guid.NewGuid().ToString("N"));
        Root = Path.Combine(TempDirectory, "root");
        Directory.CreateDirectory(Root);
        SecretFilePath = Path.Combine(TempDirectory, "config.db");
        File.WriteAllText(SecretFilePath, SecretContent);

        Client = new SftpEngineClient(new LocalFileSystem(Root));
        Client.Service.OnData(SftpEngineClient.Init());
        Client.Responses.Clear();
    }

    protected string TempDirectory { get; }
    protected string Root { get; }
    protected string SecretFilePath { get; }
    private protected SftpEngineClient Client { get; }

    /// <summary>The file on disk for a virtual path.</summary>
    protected string Physical(string virtualPath) => Path.Combine(Root, virtualPath.TrimStart('/'));

    public void Dispose()
    {
        Client.Dispose();
        try { Directory.Delete(TempDirectory, recursive: true); } catch { }
    }
}
