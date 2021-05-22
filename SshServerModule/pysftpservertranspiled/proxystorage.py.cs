//// Proxy SFTP storage. Forward each request to another SFTP server.

//using paramiko;

//using SFTPAbstractServerStorage = pysftpserver.abstractstorage.SFTPAbstractServerStorage;

//using stat_to_longname = pysftpserver.stat_helpers.stat_to_longname;

//using os;

//using sys;

//using socket;

//using getuser = getpass.getuser;

//using System.Collections;

//using System;

//using System.Collections.Generic;

//using System.Linq;

//public static class proxystorage {
    
//    // 
//    //     The server class needs not found exceptions to be instances of OSError.
//    //     In Python 3, IOError (thrown by paramiko on fail) is a subclass of OSError.
//    //     In Python 2 instaead, IOError and OSError both derive from EnvironmentError.
//    //     So let's wrap it!
//    //     
//    public static Func<object, object> exception_wrapper(object method) {
//        Func<object, object, object> _wrapper = (kwargs,args) => {
//            try {
//                return method(args, kwargs);
//            } catch (IOError) {
//                if (!(e is OSError)) {
//                    throw new OSError(e.errno, e.strerror);
//                } else {
//                    throw new IOError();
//                }
//            }
//        };
//        return _wrapper;
//    }
    
//    // Proxy SFTP storage.
//    //     Uses a Paramiko client to forward requests to another SFTP server.
//    //     
//    public class SFTPServerProxyStorage
//        : SFTPAbstractServerStorage {
        
//        public object client;
        
//        public object home;
        
//        public object hostname;
        
//        public void password;
        
//        public list pkeys;
        
//        public int port;
        
//        public object transport;
        
//        public object username;
        
//        // Convert:
//        //             os module flags and mode -> Paramiko file open mode.
//        //         Note: mode is ignored ATM.
//        //         
        
//        public static string flags_to_mode(object flags, object mode) {
//            var paramiko_mode = "";
//            if (flags & os.O_WRONLY || flags & os.O_WRONLY && flags & os.O_TRUNC) {
//                paramiko_mode = "w";
//            } else if (flags & os.O_RDWR && flags & os.O_APPEND) {
//                paramiko_mode = "a+";
//            } else if (flags & os.O_RDWR && flags & os.O_CREAT) {
//                paramiko_mode = "w+";
//            } else if (flags & os.O_APPEND) {
//                paramiko_mode = "a";
//            } else if (flags & os.O_RDWR && flags & os.O_TRUNC) {
//                paramiko_mode = "w+";
//            } else if (flags & os.O_RDWR) {
//                paramiko_mode = "r+";
//            } else if (flags & os.O_CREAT) {
//                paramiko_mode = "w";
//            } else {
//                // OS.O_RDONLY fallback to read
//                paramiko_mode = "r";
//            }
//            if (flags & os.O_CREAT && flags & os.O_EXCL) {
//                paramiko_mode += "x";
//            }
//            return paramiko_mode;
//        }
        
//        public SFTPServerProxyStorage(
//            object remote,
//            void key = null,
//            void port = null,
//            void ssh_config_path = null,
//            bool ssh_agent = false,
//            void known_hosts_path = null) {
//            if (remote.Contains("@")) {
//                var _tup_1 = remote.split("@", 1);
//                this.username = _tup_1.Item1;
//                this.hostname = _tup_1.Item2;
//            } else {
//                this.username = null;
//                this.hostname = remote;
//            }
//            this.password = null;
//            if (this.username && this.username.Contains(":")) {
//                var _tup_2 = this.username.split(":", 1);
//                this.username = _tup_2.Item1;
//                this.password = _tup_2.Item2;
//            }
//            this.port = null;
//            if (ssh_config_path) {
//                try {
//                    using (var c_file = open(os.path.expanduser(ssh_config_path))) {
//                        ssh_config = paramiko.SSHConfig();
//                        ssh_config.parse(c_file);
//                        c = ssh_config.lookup(this.hostname);
//                        this.hostname = c.get("hostname", this.hostname);
//                        this.username = c.get("user", this.username);
//                        this.port = Convert.ToInt32(c.get("port", port));
//                        key = c.get("identityfile", key);
//                    }
//                } catch (Exception) {
//                    // it could be safe to continue anyway,
//                    // because parameters could have been manually specified
//                    Console.WriteLine("Error while parsing ssh_config file: {}. Trying to continue anyway...".format(e));
//                }
//            }
//            // Set default values
//            if (!this.username) {
//                this.username = getuser();
//            }
//            if (!this.port) {
//                this.port = port ? port : 22;
//            }
//            this.pkeys = new List<object>();
//            if (ssh_agent) {
//                try {
//                    var agent = paramiko.agent.Agent();
//                    this.pkeys.append(agent.get_keys());
//                    if (!this.pkeys) {
//                        agent.close();
//                        Console.WriteLine("SSH agent didn't provide any valid key. Trying to continue...");
//                    }
//                } catch {
//                    agent.close();
//                    Console.WriteLine("SSH agent speaks a non-compatible protocol. Ignoring it.");
//                }
//            }
//            if (key && !this.password && !this.pkeys) {
//                key = os.path.expanduser(key);
//                try {
//                    this.pkeys.append(paramiko.RSAKey.from_private_key_file(key));
//                } catch {
//                    Console.WriteLine("It seems that your private key is encrypted. Please configure me to use ssh_agent.");
//                    sys.exit(1);
//                } catch (Exception) {
//                    Console.WriteLine("Something went wrong while opening {}. Exiting.".format(key));
//                    sys.exit(1);
//                }
//            } else if (!key && !this.password && !this.pkeys) {
//                Console.WriteLine("You need to specify either a password, an identity or to enable the ssh-agent support.");
//                sys.exit(1);
//            }
//            try {
//                this.transport = paramiko.Transport((this.hostname, this.port));
//            } catch {
//                Console.WriteLine("Hostname not known. Are you sure you inserted it correctly?");
//                sys.exit(1);
//            }
//            try {
//                this.transport.start_client();
//                if (known_hosts_path) {
//                    var known_hosts = paramiko.HostKeys();
//                    known_hosts_path = os.path.realpath(os.path.expanduser(known_hosts_path));
//                    try {
//                        known_hosts.load(known_hosts_path);
//                    } catch (IOError) {
//                        Console.WriteLine("Error while loading known hosts file at {}. Exiting...".format(known_hosts_path));
//                        sys.exit(1);
//                    }
//                    var ssh_host = this.port == 22 ? this.hostname : "[{}]:{}".format(this.hostname, this.port);
//                    var pub_k = this.transport.get_remote_server_key();
//                    if (known_hosts.keys().Contains(ssh_host) && !known_hosts.check(ssh_host, pub_k)) {
//                        Console.WriteLine("Security warning: remote key fingerprint {} for hostname {} didn't match the one in known_hosts {}. Exiting...".format(pub_k.get_base64(), ssh_host, known_hosts.lookup(this.hostname)));
//                        sys.exit(1);
//                    }
//                }
//                if (this.password) {
//                    this.transport.auth_password(username: this.username, password: this.password);
//                } else {
//                    foreach (var pkey in this.pkeys) {
//                        try {
//                            this.transport.auth_publickey(username: this.username, key: pkey);
//                            break;
//                        } catch {
//                            Console.WriteLine("Authentication with identity {}... failed".format(pkey.get_base64()[::10]));
//                        }
//                    }
//                }
//            } catch {
//                Console.WriteLine("None of the provided authentication methods worked. Exiting.");
//                this.transport.close();
//                sys.exit(1);
//            }
//            this.client = paramiko.SFTPClient.from_transport(this.transport);
//            // Let's retrieve the current dir
//            this.client.chdir(".");
//            this.home = this.client.getcwd();
//        }
        
//        // Verify that requested filename is accessible.
//        // 
//        //         Can always return True in this case.
//        //         
//        public virtual bool verify(object filename) {
//            return true;
//        }
        
//        // stat, lstat and fstat requests.
//        // 
//        //         Return a dictionary of stats.
//        //         Filename is an handle in the fstat variant.
//        //         
//        [exception_wrapper]
//        public virtual Dictionary<string, object> stat(object filename, void parent = null, bool lstat = false, bool fstat = false) {
//            object longname;
//            object _stat;
//            if (!lstat && fstat) {
//                // filename is an handle
//                _stat = filename.stat();
//            } else if (lstat) {
//                _stat = this.client.lstat(filename);
//            } else {
//                try {
//                    _stat = this.client.stat(!parent ? filename : os.path.join(parent, filename));
//                } catch {
//                    // we could have a broken symlink
//                    // but lstat could be false:
//                    // this happens in case of readdir responses
//                    _stat = this.client.lstat(!parent ? filename : os.path.join(parent, filename));
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
//        //         
//        [exception_wrapper]
//        public virtual void setstat(object filename, object attrs, bool fsetstat = false) {
//            if (attrs.Contains(new byte[] { (byte)'s', (byte)'i', (byte)'z', (byte)'e' }) && !fsetstat) {
//                this.client.truncate(filename, attrs[new byte[] { (byte)'s', (byte)'i', (byte)'z', (byte)'e' }]);
//            } else if (attrs.Contains(new byte[] { (byte)'s', (byte)'i', (byte)'z', (byte)'e' })) {
//                filename.truncate(attrs[new byte[] { (byte)'s', (byte)'i', (byte)'z', (byte)'e' }]);
//            }
//            var _chown = all(from k in (new byte[] { (byte)'u', (byte)'i', (byte)'d' }, new byte[] { (byte)'g', (byte)'i', (byte)'d' })
//                select attrs.Contains(k));
//            if (_chown && !fsetstat) {
//                this.client.chown(filename, attrs[new byte[] { (byte)'u', (byte)'i', (byte)'d' }], attrs[new byte[] { (byte)'g', (byte)'i', (byte)'d' }]);
//            } else if (_chown) {
//                filename.chown(attrs[new byte[] { (byte)'u', (byte)'i', (byte)'d' }], attrs[new byte[] { (byte)'g', (byte)'i', (byte)'d' }]);
//            }
//            if (attrs.Contains(new byte[] { (byte)'p', (byte)'e', (byte)'r', (byte)'m' }) && !fsetstat) {
//                this.client.chmod(filename, attrs[new byte[] { (byte)'p', (byte)'e', (byte)'r', (byte)'m' }]);
//            } else if (attrs.Contains(new byte[] { (byte)'p', (byte)'e', (byte)'r', (byte)'m' })) {
//                filename.chmod(attrs[new byte[] { (byte)'p', (byte)'e', (byte)'r', (byte)'m' }]);
//            }
//            var _utime = all(from k in (new byte[] { (byte)'a', (byte)'t', (byte)'i', (byte)'m', (byte)'e' }, new byte[] { (byte)'m', (byte)'t', (byte)'i', (byte)'m', (byte)'e' })
//                select attrs.Contains(k));
//            if (_utime && !fsetstat) {
//                this.client.utime(filename, (attrs[new byte[] { (byte)'a', (byte)'t', (byte)'i', (byte)'m', (byte)'e' }], attrs[new byte[] { (byte)'m', (byte)'t', (byte)'i', (byte)'m', (byte)'e' }]));
//            } else if (_utime) {
//                filename.utime((attrs[new byte[] { (byte)'a', (byte)'t', (byte)'i', (byte)'m', (byte)'e' }], attrs[new byte[] { (byte)'m', (byte)'t', (byte)'i', (byte)'m', (byte)'e' }]));
//            }
//        }
        
//        // Return an iterator over the files in filename.
//        [exception_wrapper]
//        public virtual List<object> opendir(object filename) {
//            return from f in this.client.listdir(filename) + new List<object> {
//                ".",
//                ".."
//            }
//                select f.encode();
//        }
        
//        // Return the file handle.
//        // 
//        //         In Paramiko there are no flags:
//        //         The mode indicates how the file is to be opened:
//        //             'r' for reading,
//        //             'w' for writing (truncating an existing file),
//        //             'a' for appending,
//        //             'r+' for reading/writing,
//        //             'w+' for reading/writing (truncating an existing file),
//        //             'a+' for reading/appending.
//        //             'x' indicates that the operation should only succeed if
//        //                 the file was created and did not previously exist.
//        //         
//        [exception_wrapper]
//        public virtual void open(object filename, object flags, object mode) {
//            var paramiko_mode = SFTPServerProxyStorage.flags_to_mode(flags, mode);
//            return this.client.open(filename, paramiko_mode);
//        }
        
//        // Create directory with given mode.
//        [exception_wrapper]
//        public virtual void mkdir(object filename, object mode) {
//            this.client.mkdir(filename, mode);
//        }
        
//        // Remove directory.
//        [exception_wrapper]
//        public virtual void rmdir(object filename) {
//            this.client.rmdir(filename);
//        }
        
//        // Remove file.
//        [exception_wrapper]
//        public virtual void rm(object filename) {
//            this.client.remove(filename);
//        }
        
//        // Move/rename file.
//        [exception_wrapper]
//        public virtual void rename(object oldpath, object newpath) {
//            this.client.rename(oldpath, newpath);
//        }
        
//        // Symlink file.
//        [exception_wrapper]
//        public virtual void symlink(object linkpath, object targetpath) {
//            this.client.symlink(targetpath, linkpath);
//        }
        
//        // Readlink of filename.
//        [exception_wrapper]
//        public virtual void readlink(object filename) {
//            var l = this.client.readlink(filename);
//            return l.encode();
//        }
        
//        // Write chunk at offset of handle.
//        public virtual bool write(object handle, object off, object chunk) {
//            var _success1 = false;
//            try {
//                handle.seek(off);
//                handle.write(chunk);
//                _success1 = true;
//            } catch {
//                return false;
//            }
//            if (_success1) {
//                return true;
//            }
//        }
        
//        // Read from the handle size, starting from offset off.
//        public virtual void read(object handle, object off, object size) {
//            handle.seek(off);
//            return handle.read(size);
//        }
        
//        // Close the file handle.
//        [exception_wrapper]
//        public virtual void close(object handle) {
//            handle.close();
//        }
//    }
//}
