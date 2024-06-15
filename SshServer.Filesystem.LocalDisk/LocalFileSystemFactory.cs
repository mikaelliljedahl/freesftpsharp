using SshServer.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SshServer.Filesystem.LocalDisk
{
    public class LocalFileSystemFactory : IFileSystemFactory
    {
        private ISettingsRepository _settingsRepository;

        public LocalFileSystemFactory(ISettingsRepository settingsRepository)
        {
            _settingsRepository = settingsRepository;

        }
        public IFileSystem GetFileSystem(string username)
        {
            var user = _settingsRepository.GetUser(username);

            LocalFileSystem fs = new LocalFileSystem(user.UserRootDirectory);
            return fs;
        }

    }
}
