namespace SshServer.Interfaces.Storage;

public interface IFileSystemFactory
{
    public IFileSystem GetFileSystem(string username);
}
