//// 
//// The server.
//// Handle requests, deliver them to the storage and then return the status.
//// 
//// Python 2/3 compatibility:
////     pysftpserver natively speaks bytes.
////     So make sure to correctly handle them, specifically in Python 3.
////     In addition, please note that arguments passed to the storage are in bytes
////     too.
//// 


//using SFTPException = pysftpexceptions.SFTPException;

//using SFTPForbidden = pysftpexceptions.SFTPForbidden;

//using SFTPNotFound = pysftpexceptions.SFTPNotFound;

//using System.Collections.Generic;

//using System.Linq;

//using System;

//public static class server {
    
//    public static int SSH2_FX_OK = 0;
    
//    public static int SSH2_FX_EOF = 1;
    
//    public static int SSH2_FX_NO_SUCH_FILE = 2;
    
//    public static int SSH2_FX_PERMISSION_DENIED = 3;
    
//    public static int SSH2_FX_FAILURE = 4;
    
//    public static int SSH2_FX_OP_UNSUPPORTED = 8;
    
//    public static int SSH2_FXP_INIT = 1;
    
//    public static int SSH2_FXP_OPEN = 3;
    
//    public static int SSH2_FXP_CLOSE = 4;
    
//    public static int SSH2_FXP_READ = 5;
    
//    public static int SSH2_FXP_WRITE = 6;
    
//    public static int SSH2_FXP_LSTAT = 7;
    
//    public static int SSH2_FXP_FSTAT = 8;
    
//    public static int SSH2_FXP_SETSTAT = 9;
    
//    public static int SSH2_FXP_FSETSTAT = 10;
    
//    public static int SSH2_FXP_OPENDIR = 11;
    
//    public static int SSH2_FXP_READDIR = 12;
    
//    public static int SSH2_FXP_REMOVE = 13;
    
//    public static int SSH2_FXP_MKDIR = 14;
    
//    public static int SSH2_FXP_RMDIR = 15;
    
//    public static int SSH2_FXP_REALPATH = 16;
    
//    public static int SSH2_FXP_STAT = 17;
    
//    public static int SSH2_FXP_RENAME = 18;
    
//    public static int SSH2_FXP_READLINK = 19;
    
//    public static int SSH2_FXP_SYMLINK = 20;
    
//    public static int SSH2_FXP_VERSION = 2;
    
//    public static int SSH2_FXP_STATUS = 101;
    
//    public static int SSH2_FXP_HANDLE = 102;
    
//    public static int SSH2_FXP_DATA = 103;
    
//    public static int SSH2_FXP_NAME = 104;
    
//    public static int SSH2_FXP_ATTRS = 105;
    
//    public static int SSH2_FXP_EXTENDED = 200;
    
//    public static int SSH2_FILEXFER_VERSION = 3;
    
//    public static int SSH2_FXF_READ = 0x00000001;
    
//    public static int SSH2_FXF_WRITE = 0x00000002;
    
//    public static int SSH2_FXF_APPEND = 0x00000004;
    
//    public static int SSH2_FXF_CREAT = 0x00000008;
    
//    public static int SSH2_FXF_TRUNC = 0x00000010;
    
//    public static int SSH2_FXF_EXCL = 0x00000020;
    
//    public static int SSH2_FILEXFER_ATTR_SIZE = 0x00000001;
    
//    public static int SSH2_FILEXFER_ATTR_UIDGID = 0x00000002;
    
//    public static int SSH2_FILEXFER_ATTR_PERMISSIONS = 0x00000004;
    
//    public static int SSH2_FILEXFER_ATTR_ACMODTIME = 0x00000008;
    
//    public static uint SSH2_FILEXFER_ATTR_EXTENDED = 0x80000000;
    
//    public class SFTPServer
//        : object {
        
//        public int buffer_size;
        
//        public Dictionary<object,object> dirs;
        
//        public object fd_in;
        
//        public object fd_out;
        
//        public Dictionary<object,object> files;
        
//        public int handle_cnt;
        
//        public Dictionary<object,object> handles;
        
//        public object hook;
        
//        public string input_queue;
        
//        public file logfile;
        
//        public string output_queue;
        
//        public string payload;
        
//        public object raise_on_error;
        
//        public object storage;
        
//        public SFTPServer(
//            object storage,
//            void hook = null,
//            void logfile = null,
//            int fd_in = 0,
//            int fd_out = 1,
//            bool raise_on_error = false) {
//            this.input_queue = new byte[] {  };
//            this.output_queue = new byte[] {  };
//            this.payload = new byte[] {  };
//            this.fd_in = fd_in;
//            this.fd_out = fd_out;
//            this.buffer_size = 8192;
//            this.storage = storage;
//            this.hook = hook;
//            if (hook) {
//                this.hook.server = this;
//            }
//            this.handles = new Dictionary<object,object>();
//            this.dirs = new Dictionary<object,object>();
//            this.files = new Dictionary<object,object>();
//            this.handle_cnt = 0;
//            this.raise_on_error = raise_on_error;
//            this.logfile = null;
//            if (logfile) {
//                this.logfile = open(logfile, "a");
//                sys.stderr = this.logfile;
//            }
//        }
        
//        public virtual void new_handle(void filename, object flags = 0, object attrs = new Dictionary<object,object>(), bool is_opendir = false) {
//            object handle;
//            if (is_opendir) {
//                handle = this.storage.opendir(filename);
//            } else {
//                var os_flags = 0x00000000;
//                if (flags & SSH2_FXF_READ && flags & SSH2_FXF_WRITE) {
//                    os_flags |= os.O_RDWR;
//                } else if (flags & SSH2_FXF_READ) {
//                    os_flags |= os.O_RDONLY;
//                } else if (flags & SSH2_FXF_WRITE) {
//                    os_flags |= os.O_WRONLY;
//                }
//                if (flags & SSH2_FXF_APPEND) {
//                    os_flags |= os.O_APPEND;
//                }
//                if (flags & SSH2_FXF_CREAT) {
//                    os_flags |= os.O_CREAT;
//                }
//                if (flags & SSH2_FXF_TRUNC && flags & SSH2_FXF_CREAT) {
//                    os_flags |= os.O_TRUNC;
//                }
//                if (flags & SSH2_FXF_EXCL && flags & SSH2_FXF_CREAT) {
//                    os_flags |= os.O_EXCL;
//                }
//                var mode = attrs.get(new byte[] { (byte)'p', (byte)'e', (byte)'r', (byte)'m' }, 0666);
//                handle = this.storage.open(filename, os_flags, mode);
//            }
//            if (this.handle_cnt == 0xffffffffffffffff) {
//                throw new OverflowError();
//            }
//            this.handle_cnt += 1;
//            var handle_id = bytes(this.handle_cnt);
//            this.handles[handle_id] = handle;
//            if (is_opendir) {
//                this.dirs[handle_id] = filename;
//            } else {
//                this.files[handle_id] = filename;
//            }
//            return handle_id;
//        }
        
//        // Recover the name of a file or directory from its handle id.
//        // 
//        //         Args:
//        //             handle_id (int): The handle id of the file or directory.
//        // 
//        //         Returns:
//        //             str: The name of the directory or file corresponding to the
//        //                 provided handle id. None if neither a directory nor a file
//        //                 is found.
//        //             bool: True if the recovered filename is a directory. False if
//        //                 it is a file. None if nothing is found.
//        //         
//        public virtual object[] get_filename_from_handle_id(object handle_id) {
//            if (this.dirs.Contains(handle_id)) {
//                return Tuple.Create(this.dirs[handle_id], true);
//            }
//            if (this.files.Contains(handle_id)) {
//                return Tuple.Create(this.files[handle_id], false);
//            }
//            return Tuple.Create(null, null);
//        }
        
//        public virtual void log(string txt) {
//            if (!this.logfile) {
//                return;
//            }
//            this.logfile.write(txt + "\n");
//            this.logfile.flush();
//        }
        
//        public virtual void consume_int() {
//            var _tup_1 = @struct.unpack(">I", this.payload[0::4]);
//            var value = _tup_1.Item1;
//            this.payload = this.payload[4];
//            return value;
//        }
        
//        public virtual void consume_int64() {
//            var _tup_1 = @struct.unpack(">Q", this.payload[0::8]);
//            var value = _tup_1.Item1;
//            this.payload = this.payload[8];
//            return value;
//        }
        
//        public virtual string consume_string() {
//            var slen = this.consume_int();
//            var s = this.payload[0::slen];
//            this.payload = this.payload[slen];
//            return s;
//        }
        
//        public virtual Tuple<object, object> consume_handle_and_id() {
//            var handle_id = this.consume_string();
//            return Tuple.Create(this.handles[handle_id], handle_id);
//        }
        
//        public virtual Dictionary<object, object> consume_attrs() {
//            var attrs = new Dictionary<object, object> {
//            };
//            var flags = this.consume_int();
//            if (flags & SSH2_FILEXFER_ATTR_SIZE) {
//                attrs[new byte[] { (byte)'s', (byte)'i', (byte)'z', (byte)'e' }] = this.consume_int64();
//            }
//            if (flags & SSH2_FILEXFER_ATTR_UIDGID) {
//                attrs[new byte[] { (byte)'u', (byte)'i', (byte)'d' }] = this.consume_int();
//                attrs[new byte[] { (byte)'g', (byte)'i', (byte)'d' }] = this.consume_int();
//            }
//            if (flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
//                attrs[new byte[] { (byte)'p', (byte)'e', (byte)'r', (byte)'m' }] = this.consume_int();
//            }
//            if (flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
//                attrs[new byte[] { (byte)'a', (byte)'t', (byte)'i', (byte)'m', (byte)'e' }] = this.consume_int();
//                attrs[new byte[] { (byte)'m', (byte)'t', (byte)'i', (byte)'m', (byte)'e' }] = this.consume_int();
//            }
//            if (flags & SSH2_FILEXFER_ATTR_EXTENDED) {
//                var count = this.consume_int();
//                if (count) {
//                    attrs[new byte[] { (byte)'e', (byte)'x', (byte)'t', (byte)'e', (byte)'n', (byte)'d', (byte)'e', (byte)'d' }] = (from i in Enumerable.Range(0, count)
//                        select new Dictionary<object, object> {
//                            {
//                                this.consume_string(),
//                                this.consume_string()}}).ToList();
//                }
//            }
//            return attrs;
//        }
        
//        public virtual void consume_filename(object @default = null) {
//            var filename = this.consume_string();
//            if (filename == new byte[] { (byte)'.' }) {
//                filename = this.storage.home.encode();
//            } else if (filename.Count == 0) {
//                if (@default) {
//                    filename = @default;
//                } else {
//                    throw SFTPNotFound();
//                }
//            }
//            if (this.storage.verify(filename)) {
//                return filename;
//            }
//            throw SFTPForbidden();
//        }
        
//        public virtual string encode_attrs(object attrs) {
//            var flags = SSH2_FILEXFER_ATTR_SIZE | SSH2_FILEXFER_ATTR_UIDGID | SSH2_FILEXFER_ATTR_PERMISSIONS | SSH2_FILEXFER_ATTR_ACMODTIME;
//            return @struct.pack(">IQIIIII", flags, attrs[new byte[] { (byte)'s', (byte)'i', (byte)'z', (byte)'e' }], attrs[new byte[] { (byte)'u', (byte)'i', (byte)'d' }], attrs[new byte[] { (byte)'g', (byte)'i', (byte)'d' }], attrs[new byte[] { (byte)'p', (byte)'e', (byte)'r', (byte)'m' }], Convert.ToInt32(attrs[new byte[] { (byte)'a', (byte)'t', (byte)'i', (byte)'m', (byte)'e' }]), Convert.ToInt32(attrs[new byte[] { (byte)'m', (byte)'t', (byte)'i', (byte)'m', (byte)'e' }]));
//        }
        
//        public virtual void send_msg(object msg) {
//            var msg_len = @struct.pack(">I", msg.Count);
//            this.output_queue += msg_len + msg;
//        }
        
//        public virtual void send_status(void sid, int status, void exc = null) {
//            if (status != SSH2_FX_OK && this.raise_on_error) {
//                if (exc) {
//                    throw exc;
//                }
//                throw SFTPException();
//            }
//            this.log(String.Format("sending status %d", status));
//            var msg = @struct.pack(">BII", SSH2_FXP_STATUS, sid, status);
//            if (exc && exc.msg) {
//                msg += @struct.pack(">I", exc.msg.Count) + exc.msg;
//                msg += @struct.pack(">I", 0);
//            }
//            this.send_msg(msg);
//        }
        
//        public virtual void send_data(object sid, object buf, int size) {
//            var msg = @struct.pack(">BII", SSH2_FXP_DATA, sid, size);
//            msg += buf;
//            this.send_msg(msg);
//        }
        
//        public virtual void run() {
//            while (true) {
//                if (this.run_once()) {
//                    return;
//                }
//            }
//        }
        
//        public virtual bool run_once() {
//            var wait_write = new List<object>();
//            if (this.output_queue.Count > 0) {
//                wait_write = new List<int> {
//                    this.fd_out
//                };
//            }
//            var _tup_1 = select.select(new List<int> {
//                this.fd_in
//            }, wait_write, new List<object>());
//            var rlist = _tup_1.Item1;
//            var wlist = _tup_1.Item2;
//            var xlist = _tup_1.Item3;
//            if (rlist.Contains(this.fd_in)) {
//                var buf = os.read(this.fd_in, this.buffer_size);
//                if (buf.Count <= 0) {
//                    return true;
//                }
//                this.input_queue += buf;
//                this.process();
//            }
//            if (wlist.Contains(this.fd_out)) {
//                var rlen = os.write(this.fd_out, this.output_queue);
//                if (rlen <= 0) {
//                    return true;
//                }
//                this.output_queue = this.output_queue[rlen];
//            }
//        }
        
//        public virtual void process() {
//            while (true) {
//                if (this.input_queue.Count < 5) {
//                    return;
//                }
//                var _tup_1 = @struct.unpack(">IB", this.input_queue[0::5]);
//                var msg_len = _tup_1.Item1;
//                var msg_type = _tup_1.Item2;
//                if (this.input_queue.Count < msg_len + 4) {
//                    return;
//                }
//                this.payload = this.input_queue[5::(4  +  msg_len)];
//                this.input_queue = this.input_queue[msg_len + 4];
//                if (msg_type == SSH2_FXP_INIT) {
//                    var msg = @struct.pack(">BI", SSH2_FXP_VERSION, SSH2_FILEXFER_VERSION);
//                    this.send_msg(msg);
//                    if (this.hook) {
//                        this.hook.init();
//                    }
//                } else {
//                    var msg_id = this.consume_int();
//                    if (this.table.keys().ToList().Contains(msg_type)) {
//                        try {
//                            this.table[msg_type](this, msg_id);
//                        } catch (SFTPForbidden) {
//                            this.send_status(msg_id, SSH2_FX_PERMISSION_DENIED, e);
//                        } catch (SFTPNotFound) {
//                            this.send_status(msg_id, SSH2_FX_NO_SUCH_FILE, e);
//                        } catch (OSError) {
//                            if (e.errno == errno.ENOENT) {
//                                this.send_status(msg_id, SSH2_FX_NO_SUCH_FILE, SFTPNotFound());
//                            } else {
//                                this.send_status(msg_id, SSH2_FX_FAILURE);
//                            }
//                        } catch (Exception) {
//                            this.send_status(msg_id, SSH2_FX_FAILURE);
//                        }
//                    } else {
//                        this.send_status(msg_id, SSH2_FX_OP_UNSUPPORTED);
//                    }
//                }
//            }
//        }
        
//        public virtual void send_dummy_item(object sid, object item, void filename) {
//            object longname;
//            // In case of readlink responses
//            // There's no need to add the attrs,
//            // But longname is still needed
//            // item is the linked and filename is the link
//            var attrs = this.storage.stat(filename, lstat: true);
//            var msg = @struct.pack(">BII", SSH2_FXP_NAME, sid, 1);
//            msg += @struct.pack(">I", item.Count) + item;
//            if (attrs.Contains(new byte[] { (byte)'l', (byte)'o', (byte)'n', (byte)'g', (byte)'n', (byte)'a', (byte)'m', (byte)'e' }) && attrs[new byte[] { (byte)'l', (byte)'o', (byte)'n', (byte)'g', (byte)'n', (byte)'a', (byte)'m', (byte)'e' }]) {
//                // longname
//                longname = attrs[new byte[] { (byte)'l', (byte)'o', (byte)'n', (byte)'g', (byte)'n', (byte)'a', (byte)'m', (byte)'e' }];
//            } else {
//                longname = item;
//            }
//            msg += @struct.pack(">I", longname.Count) + longname;
//            this.send_msg(msg);
//        }
        
//        public virtual void send_item(object sid, void item, void parent_dir = null) {
//            object longname;
//            object attrs;
//            if (parent_dir) {
//                // in case of readdir response
//                attrs = this.storage.stat(item, parent: parent_dir);
//            } else {
//                attrs = this.storage.stat(item);
//            }
//            var msg = @struct.pack(">BII", SSH2_FXP_NAME, sid, 1);
//            msg += @struct.pack(">I", item.Count) + item;
//            if (attrs.Contains(new byte[] { (byte)'l', (byte)'o', (byte)'n', (byte)'g', (byte)'n', (byte)'a', (byte)'m', (byte)'e' }) && attrs[new byte[] { (byte)'l', (byte)'o', (byte)'n', (byte)'g', (byte)'n', (byte)'a', (byte)'m', (byte)'e' }]) {
//                // longname
//                longname = attrs[new byte[] { (byte)'l', (byte)'o', (byte)'n', (byte)'g', (byte)'n', (byte)'a', (byte)'m', (byte)'e' }];
//            } else {
//                longname = item;
//            }
//            msg += @struct.pack(">I", longname.Count) + longname;
//            msg += this.encode_attrs(attrs);
//            this.send_msg(msg);
//        }
        
//        public virtual void _realpath(object sid) {
//            var filename = this.consume_filename(@default: new byte[] { (byte)'.' });
//            if (this.hook) {
//                this.hook.realpath(filename);
//            }
//            this.send_item(sid, filename);
//        }
        
//        public virtual void _stat(object sid) {
//            var filename = this.consume_filename();
//            if (this.hook) {
//                this.hook.stat(filename);
//            }
//            var attrs = this.storage.stat(filename);
//            var msg = @struct.pack(">BI", SSH2_FXP_ATTRS, sid);
//            msg += this.encode_attrs(attrs);
//            this.send_msg(msg);
//        }
        
//        public virtual void _lstat(object sid) {
//            var filename = this.consume_filename();
//            if (this.hook) {
//                this.hook.lstat(filename);
//            }
//            var attrs = this.storage.stat(filename, lstat: true);
//            var msg = @struct.pack(">BI", SSH2_FXP_ATTRS, sid);
//            msg += this.encode_attrs(attrs);
//            this.send_msg(msg);
//        }
        
//        public virtual void _fstat(object sid) {
//            var handle_id = this.consume_string();
//            if (this.hook) {
//                this.hook.fstat(handle_id);
//            }
//            var handle = this.handles[handle_id];
//            var attrs = this.storage.stat(handle, fstat: true);
//            var msg = @struct.pack(">BI", SSH2_FXP_ATTRS, sid);
//            msg += this.encode_attrs(attrs);
//            this.send_msg(msg);
//        }
        
//        public virtual void _setstat(object sid) {
//            var filename = this.consume_filename();
//            var attrs = this.consume_attrs();
//            if (this.hook) {
//                this.hook.setstat(filename, attrs);
//            }
//            this.storage.setstat(filename, attrs);
//            this.send_status(sid, SSH2_FX_OK);
//        }
        
//        public virtual void _fsetstat(object sid) {
//            var handle_id = this.consume_string();
//            var handle = this.handles[handle_id];
//            var attrs = this.consume_attrs();
//            if (this.hook) {
//                this.hook.fsetstat(handle_id, attrs);
//            }
//            this.storage.setstat(handle, attrs, fsetstat: true);
//            this.send_status(sid, SSH2_FX_OK);
//        }
        
//        public virtual void _opendir(object sid) {
//            var filename = this.consume_filename();
//            if (this.hook) {
//                this.hook.opendir(filename);
//            }
//            var handle_id = this.new_handle(filename, is_opendir: true);
//            var msg = @struct.pack(">BII", SSH2_FXP_HANDLE, sid, handle_id.Count);
//            msg += handle_id;
//            this.send_msg(msg);
//        }
        
//        public virtual object _readdir(object sid) {
//            var _tup_1 = this.consume_handle_and_id();
//            var handle = _tup_1.Item1;
//            var handle_id = _tup_1.Item2;
//            if (this.hook) {
//                this.hook.readdir(handle_id);
//            }
//            try {
//                var item = next(handle);
//                this.send_item(sid, item, parent_dir: this.dirs[handle_id]);
//            } catch (StopIteration) {
//                this.send_status(sid, SSH2_FX_EOF);
//            }
//        }
        
//        public virtual object _close(object sid) {
//            // here we need to hold the handle id
//            var handle_id = this.consume_string();
//            if (this.hook) {
//                this.hook.close(handle_id);
//            }
//            var handle = this.handles[handle_id];
//            this.storage.close(handle);
//            this.handles.Remove(handle_id);
//            try {
//                this.dirs.Remove(handle_id);
//            } catch (KeyError) {
//            }
//            this.send_status(sid, SSH2_FX_OK);
//        }
        
//        public virtual void _open(object sid) {
//            var filename = this.consume_filename();
//            var flags = this.consume_int();
//            var attrs = this.consume_attrs();
//            if (this.hook) {
//                this.hook.open(filename, flags, attrs);
//            }
//            var handle_id = this.new_handle(filename, flags, attrs);
//            var msg = @struct.pack(">BII", SSH2_FXP_HANDLE, sid, handle_id.Count);
//            msg += handle_id;
//            this.send_msg(msg);
//        }
        
//        public virtual void _read(object sid) {
//            var _tup_1 = this.consume_handle_and_id();
//            var handle = _tup_1.Item1;
//            var handle_id = _tup_1.Item2;
//            var off = this.consume_int64();
//            var size = this.consume_int();
//            if (this.hook) {
//                this.hook.read(handle_id, off, size);
//            }
//            var chunk = this.storage.read(handle, off, size);
//            if (chunk.Count == 0) {
//                this.send_status(sid, SSH2_FX_EOF);
//            } else if (chunk.Count > 0) {
//                this.send_data(sid, chunk, chunk.Count);
//            } else {
//                this.send_status(sid, SSH2_FX_FAILURE);
//            }
//        }
        
//        public virtual void _write(object sid) {
//            var _tup_1 = this.consume_handle_and_id();
//            var handle = _tup_1.Item1;
//            var handle_id = _tup_1.Item2;
//            var off = this.consume_int64();
//            var chunk = this.consume_string();
//            if (this.hook) {
//                this.hook.write(handle_id, off, chunk);
//            }
//            if (this.storage.write(handle, off, chunk)) {
//                this.send_status(sid, SSH2_FX_OK);
//            } else {
//                this.send_status(sid, SSH2_FX_FAILURE);
//            }
//        }
        
//        public virtual void _mkdir(object sid) {
//            var filename = this.consume_filename();
//            var attrs = this.consume_attrs();
//            if (this.hook) {
//                this.hook.mkdir(filename, attrs);
//            }
//            this.storage.mkdir(filename, attrs.get(new byte[] { (byte)'p', (byte)'e', (byte)'r', (byte)'m' }, 0777));
//            this.send_status(sid, SSH2_FX_OK);
//        }
        
//        public virtual void _rmdir(object sid) {
//            var filename = this.consume_filename();
//            if (this.hook) {
//                this.hook.rmdir(filename);
//            }
//            this.storage.rmdir(filename);
//            this.send_status(sid, SSH2_FX_OK);
//        }
        
//        public virtual void _rm(object sid) {
//            var filename = this.consume_filename();
//            if (this.hook) {
//                this.hook.rm(filename);
//            }
//            this.storage.rm(filename);
//            this.send_status(sid, SSH2_FX_OK);
//        }
        
//        public virtual void _rename(object sid) {
//            var oldpath = this.consume_filename();
//            var newpath = this.consume_filename();
//            if (this.hook) {
//                this.hook.rename(oldpath, newpath);
//            }
//            this.storage.rename(oldpath, newpath);
//            this.send_status(sid, SSH2_FX_OK);
//        }
        
//        public virtual void _symlink(object sid) {
//            var linkpath = this.consume_filename();
//            var targetpath = this.consume_filename();
//            if (this.hook) {
//                this.hook.symlink(linkpath, targetpath);
//            }
//            this.storage.symlink(linkpath, targetpath);
//            this.send_status(sid, SSH2_FX_OK);
//        }
        
//        public virtual void _readlink(object sid) {
//            var filename = this.consume_filename();
//            if (this.hook) {
//                this.hook.readlink(filename);
//            }
//            var link = this.storage.readlink(filename);
//            this.send_dummy_item(sid, link, filename);
//        }
        
//        public object table = new Dictionary<object, object> {
//            {
//                SSH2_FXP_REALPATH,
//                _realpath},
//            {
//                SSH2_FXP_LSTAT,
//                _lstat},
//            {
//                SSH2_FXP_FSTAT,
//                _fstat},
//            {
//                SSH2_FXP_STAT,
//                _stat},
//            {
//                SSH2_FXP_OPENDIR,
//                _opendir},
//            {
//                SSH2_FXP_READDIR,
//                _readdir},
//            {
//                SSH2_FXP_CLOSE,
//                _close},
//            {
//                SSH2_FXP_OPEN,
//                _open},
//            {
//                SSH2_FXP_READ,
//                _read},
//            {
//                SSH2_FXP_WRITE,
//                _write},
//            {
//                SSH2_FXP_MKDIR,
//                _mkdir},
//            {
//                SSH2_FXP_RMDIR,
//                _rmdir},
//            {
//                SSH2_FXP_REMOVE,
//                _rm},
//            {
//                SSH2_FXP_SETSTAT,
//                _setstat},
//            {
//                SSH2_FXP_FSETSTAT,
//                _fsetstat},
//            {
//                SSH2_FXP_RENAME,
//                _rename},
//            {
//                SSH2_FXP_SYMLINK,
//                _symlink},
//            {
//                SSH2_FXP_READLINK,
//                _readlink}};
//    }
//}
