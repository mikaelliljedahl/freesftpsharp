namespace SshServerModule.Services
{
    public interface IFileSystemFactory
    {
        public IFileSystem GetFileSystem(string username);
    }
}
