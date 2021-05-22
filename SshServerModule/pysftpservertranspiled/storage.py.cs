//// General SFTP storage. Subclass it the way you want!

//using os;

//using itertools;

//using SFTPAbstractServerStorage = pysftpserver.abstractstorage.SFTPAbstractServerStorage;

//using futimes = pysftpserver.futimes.futimes;

//using stat_to_longname = pysftpserver.stat_helpers.stat_to_longname;

//using System;

//using System.Collections.Generic;

//public static class storage {
    
//    // Simple storage class. Subclass it and override the methods.
//    public class SFTPServerStorage
//        : SFTPAbstractServerStorage {
        
//        public string home;
        
//        public SFTPServerStorage(object home, void umask = null) {
//            this.home = os.path.realpath(home);
//            os.chdir(this.home);
//            if (umask) {
//                os.umask(umask);
//            }
//        }
        
//        // Verify that requested filename is accessible.
//        // 
//        //         In this simple storage class this is always True
//        //         (and thus possibly insecure).
//        //         
//        public virtual bool verify(object filename) {
//            return true;
//        }
        
//        // stat, lstat and fstat requests.
//        // 
//        //         Return a dictionary of stats.
//        //         Filename is an handle in the fstat variant.
//        //         If parent is not None, then filename is inside parent,
//        //         and a join is needed.
//        //         This happens in case of readdir responses:
//        //         a filename (not a path) has to be returned,
//        //         but the stat call need (obviously) a full path.
//        //         
//        public virtual Dictionary<string, object> stat(object filename, bool lstat = false, bool fstat = false, void parent = null) {
//            object longname;
//            object _stat;
//            if (!lstat && fstat) {
//                // filename is an handle
//                _stat = os.fstat(filename);
//            } else if (lstat) {
//                _stat = os.lstat(filename);
//            } else {
//                try {
//                    _stat = os.stat(!parent ? filename : os.path.join(parent, filename));
//                } catch {
//                    // we could have a broken symlink
//                    // but lstat could be false:
//                    // this happens in case of readdir responses
//                    _stat = os.lstat(!parent ? filename : os.path.join(parent, filename));
//                }
//            }
//            if (fstat) {
//                longname = null;
//            } else {
//                longname = stat_to_longname(_stat, filename);
//            }
//            return new Dictionary<object, object> {
//                {
//                    new byte[] { (byte)'s', (byte)'i', (byte)'z', (byte)'e' },
//                    _stat.st_size},
//                {
//                    new byte[] { (byte)'u', (byte)'i', (byte)'d' },
//                    _stat.st_uid},
//                {
//                    new byte[] { (byte)'g', (byte)'i', (byte)'d' },
//                    _stat.st_gid},
//                {
//                    new byte[] { (byte)'p', (byte)'e', (byte)'r', (byte)'m' },
//                    _stat.st_mode},
//                {
//                    new byte[] { (byte)'a', (byte)'t', (byte)'i', (byte)'m', (byte)'e' },
//                    _stat.st_atime},
//                {
//                    new byte[] { (byte)'m', (byte)'t', (byte)'i', (byte)'m', (byte)'e' },
//                    _stat.st_mtime},
//                {
//                    new byte[] { (byte)'l', (byte)'o', (byte)'n', (byte)'g', (byte)'n', (byte)'a', (byte)'m', (byte)'e' },
//                    longname}};
//        }
        
//        // setstat and fsetstat requests.
//        // 
//        //         Filename is an handle in the fstat variant.
//        //         If you're using Python < 3.3,
//        //         you could find useful the futimes file / function.
//        //         
//        public virtual void setstat(object filename, object attrs, bool fsetstat = false) {
//            object chmod;
//            object chown;
//            object f;
//            if (!fsetstat) {
//                f = os.open(filename, os.O_WRONLY);
//                chown = os.chown;
//                chmod = os.chmod;
//            } else {
//                // filename is a fd
//                f = filename;
//                chown = os.fchown;
//                chmod = os.fchmod;
//            }
//            if (attrs.Contains(new byte[] { (byte)'s', (byte)'i', (byte)'z', (byte)'e' })) {
//                os.ftruncate(f, attrs[new byte[] { (byte)'s', (byte)'i', (byte)'z', (byte)'e' }]);
//            }
//            if (all(from k in (new byte[] { (byte)'u', (byte)'i', (byte)'d' }, new byte[] { (byte)'g', (byte)'i', (byte)'d' })
//                select attrs.Contains(k))) {
//                chown(filename, attrs[new byte[] { (byte)'u', (byte)'i', (byte)'d' }], attrs[new byte[] { (byte)'g', (byte)'i', (byte)'d' }]);
//            }
//            if (attrs.Contains(new byte[] { (byte)'p', (byte)'e', (byte)'r', (byte)'m' })) {
//                chmod(filename, attrs[new byte[] { (byte)'p', (byte)'e', (byte)'r', (byte)'m' }]);
//            }
//            if (all(from k in (new byte[] { (byte)'a', (byte)'t', (byte)'i', (byte)'m', (byte)'e' }, new byte[] { (byte)'m', (byte)'t', (byte)'i', (byte)'m', (byte)'e' })
//                select attrs.Contains(k))) {
//                if (!fsetstat) {
//                    os.utime(filename, (attrs[new byte[] { (byte)'a', (byte)'t', (byte)'i', (byte)'m', (byte)'e' }], attrs[new byte[] { (byte)'m', (byte)'t', (byte)'i', (byte)'m', (byte)'e' }]));
//                } else {
//                    futimes(filename, (attrs[new byte[] { (byte)'a', (byte)'t', (byte)'i', (byte)'m', (byte)'e' }], attrs[new byte[] { (byte)'m', (byte)'t', (byte)'i', (byte)'m', (byte)'e' }]));
//                }
//            }
//        }
        
//        // Return an iterator over the files in filename.
//        public virtual iterator opendir(object filename) {
//            return new iterator(iter(new List<string> {
//                new byte[] { (byte)'.' },
//                new byte[] { (byte)'.', (byte)'.' }
//            }), iter(os.listdir(filename)));
//        }
        
//        // Return the file handle.
//        public virtual file open(object filename, object flags, object mode) {
//            return os.open(filename, flags, mode);
//        }
        
//        // Create directory with given mode.
//        public virtual void mkdir(object filename, object mode) {
//            os.mkdir(filename, mode);
//        }
        
//        // Remove directory.
//        public virtual void rmdir(object filename) {
//            os.rmdir(filename);
//        }
        
//        // Remove file.
//        public virtual void rm(object filename) {
//            os.remove(filename);
//        }
        
//        // Move/rename file.
//        public virtual void rename(object oldpath, object newpath) {
//            os.rename(oldpath, newpath);
//        }
        
//        // Symlink file.
//        public virtual void symlink(object linkpath, object targetpath) {
//            os.symlink(targetpath, linkpath);
//        }
        
//        // Readlink of filename.
//        public virtual string readlink(object filename) {
//            return os.readlink(filename);
//        }
        
//        // Write chunk at offset of handle.
//        public virtual bool write(object handle, object off, object chunk) {
//            os.lseek(handle, off, os.SEEK_SET);
//            var rlen = os.write(handle, chunk);
//            if (rlen == chunk.Count) {
//                return true;
//            }
//        }
        
//        // Read from the handle size, starting from offset off.
//        public virtual string read(object handle, object off, object size) {
//            os.lseek(handle, off, os.SEEK_SET);
//            return os.read(handle, size);
//        }
        
//        // Close the file handle.
//        public virtual object close(object handle) {
//            try {
//                handle.close();
//            } catch (AttributeError) {
//            }
//        }
//    }
//}
