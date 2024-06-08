using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace FxSsh.SshServerModule.Services
{

    public class SftpSubsystem : IDisposable
    {

        private ILogger _logger;
        private uint channel;
        private string UserRootDirectory;
        internal EventHandler<ICollection<byte>> OnOutput;
        int sftpversion;
        bool cwdInitialized = false;

        //internal EventHandler OnClose;
        Dictionary<string, string> HandleToPathDictionary;
        Dictionary<string, Dictionary<string, FileInfo>> HandleToPathDirList;
        Dictionary<string, FileStream> HandleToFileStreamDictionary;

        public SftpSubsystem(ILogger logger, uint channel, string HomeDirectory)
        {
            this._logger = logger;
            this.channel = channel;
            this.UserRootDirectory = HomeDirectory;

            HandleToPathDictionary = new Dictionary<string, string>();
            HandleToFileStreamDictionary = new Dictionary<string, FileStream>();
            HandleToPathDirList = new Dictionary<string, Dictionary<string, FileInfo>>();
        }

        public void Dispose()
        {
            foreach (var fs in HandleToFileStreamDictionary.Values)
            {
                fs.Close();
                fs.Dispose();
            }
        }

        /// <summary>
        /// It first reads the first 5 bytes of the input, which is the length of the message and the message
        /// type. Then it reads the rest of the message and calls the appropriate function to handle the
        /// message based on the type
        /// </summary>
        /// <param name="ee">the byte array of the data received from the client</param>
        internal void OnInput(byte[] ee)
        {
            var input = Encoding.UTF8.GetString(ee);

            //uint32 length
            //byte type
            //byte[length - 1] data payload
            SshDataWorker reader = new SshDataWorker(ee);

            if (reader.DataAvailable >= 5)
            {
                var msglength = reader.ReadUInt32();
                var msgtype = (RequestPacketType)(int)reader.ReadByte();

                if (msglength > 1e6 && cwdInitialized)
                {
                    reader = new SshDataWorker(ee);
                    msgtype = (RequestPacketType)(int)reader.ReadByte();
                    //msglength = reader.ReadUInt32();
                    //msgtype = (RequestPacketType)(int)reader.ReadByte();
                }


#if DEBUG
                if (msgtype != RequestPacketType.SSH_FXP_READ &&
                    msgtype != RequestPacketType.SSH_FXP_WRITE)
                    _logger.LogInformation($"sftp command {msgtype.ToString()}, messagelength: {msglength} inputbase64: \"{Convert.ToBase64String(ee)}\" input: \"{input}\". on channel: {channel}");
#endif

                switch (msgtype)
                {
                    case RequestPacketType.SSH_FXP_INIT:
                        if (!cwdInitialized)
                        {
                            HandleInit(reader);
                        }
                        else
                        {
                            var requestIdError = reader.ReadUInt32();
                            _logger.LogInformation($"sftp command {msgtype.ToString()} unsupported in this state, requestId: {requestIdError} on channel: {channel}");

                            SendStatus(requestIdError, SftpStatusType.SSH_FX_OP_UNSUPPORTED);
                        }
                        break;

                    case RequestPacketType.SSH_FXP_VERSION:
                        HandleVersion(reader);
                        break;

                    case RequestPacketType.SSH_FXP_REALPATH:

                        HandleRealPath(reader, false);
                        break;

                    case RequestPacketType.SSH_FXP_READDIR:
                        HandleReadDir(reader);
                        break;

                    case RequestPacketType.SSH_FXP_OPENDIR:
                        HandleOpenDir(reader);
                        break;

                    case RequestPacketType.SSH_FXP_STAT: // follows symbolic links
                    case RequestPacketType.SSH_FXP_LSTAT: // does not follow symbolic links
                        HandleStat(reader);
                        break;

                    case RequestPacketType.SSH_FXP_FSTAT: // SSH_FXP_FSTAT differs from the others in that it returns status information for an open file(identified by the file handle).
                        HandleFStat(reader);
                        break;

                    case RequestPacketType.SSH_FXP_CLOSE:
                        HandleClose(reader);
                        break;

                    case RequestPacketType.SSH_FXP_OPEN:
                        HandleFileOpen(reader);
                        break;

                    case RequestPacketType.SSH_FXP_READ:
                        HandleReadFile(reader);
                        break;
                    case RequestPacketType.SSH_FXP_WRITE:
                        HandleWriteFile(reader);
                        break;

                    case RequestPacketType.SSH_FXP_REMOVE:
                        HandleRemoveFile(reader);
                        break;

                    case RequestPacketType.SSH_FXP_MKDIR:
                        HandleMakeDir(reader);
                        break;

                    case RequestPacketType.SSH_FXP_RMDIR:
                        HandleRemoveDir(reader);
                        break;

                    case RequestPacketType.SSH_FXP_RENAME:
                        HandleRename(reader);
                        break;

                    default:
                        // unsupported command
                        _logger.LogWarning($"Unsupported sftp command {msgtype.ToString()} input: \"{input}\". on channel: {channel}");
                        uint requestId = reader.ReadUInt32();
                        SendStatus(requestId, SftpStatusType.SSH_FX_OP_UNSUPPORTED);
                        break;
                }
            }
        }

        private void HandleRename(SshDataWorker reader)
        {

            uint requestId = reader.ReadUInt32();

            var oldpath = reader.ReadString(Encoding.UTF8);
            var newpath = reader.ReadString(Encoding.UTF8);

            if (oldpath.Contains(".."))
            {
                SendStatus(requestId, SftpStatusType.SSH_FX_PERMISSION_DENIED);
            }
            else
            {
                DirectoryInfo di = new DirectoryInfo(oldpath);
                if (di.Exists)
                {
                    di.MoveTo(newpath);
                    SendStatus(requestId, SftpStatusType.SSH_FX_OK);
                }
                else
                {
                    FileInfo fi = new FileInfo(oldpath);
                    if (fi.Exists)
                    {
                        fi.MoveTo(newpath);
                        SendStatus(requestId, SftpStatusType.SSH_FX_OK);
                    }
                }
            }

        }

        private void HandleRemoveDir(SshDataWorker reader)
        {

            uint requestId = reader.ReadUInt32();
            var pathtoremove = reader.ReadString(Encoding.UTF8);

            if (pathtoremove.Contains(".."))
            {
                SendStatus(requestId, SftpStatusType.SSH_FX_PERMISSION_DENIED);
            }
            else
            {
                var absolutepath = UserRootDirectory + pathtoremove;
                System.IO.DirectoryInfo di = new DirectoryInfo(absolutepath);
                try
                {
                    di.Delete();
                    SendStatus(requestId, SftpStatusType.SSH_FX_OK);
                }
                catch
                {
                    SendStatus(requestId, SftpStatusType.SSH_FX_FAILURE);
                }
            }
        }

        private void HandleMakeDir(SshDataWorker reader)
        {
            //         New directories can be created using the SSH_FXP_MKDIR request.It has the following format:
            //         uint32 id
            //     string path
            //     ATTRS attrs
            uint requestId = reader.ReadUInt32();
            var newpath = reader.ReadString(Encoding.UTF8);
            // what about ATTRS???

            if (newpath.Contains(".."))
            {
                SendStatus(requestId, SftpStatusType.SSH_FX_PERMISSION_DENIED);
            }
            else
            {
                var absolutepath = UserRootDirectory + newpath;
                System.IO.DirectoryInfo di = new DirectoryInfo(absolutepath);
                try
                {
                    di.Create();
                    SendStatus(requestId, SftpStatusType.SSH_FX_OK);
                }
                catch
                {
                    SendStatus(requestId, SftpStatusType.SSH_FX_FAILURE);
                }
            }
        }

        private void HandleRemoveFile(SshDataWorker reader)
        {

            uint requestId = reader.ReadUInt32();
            var filename = reader.ReadString(Encoding.UTF8); // SSH_FXP_REMOVE
            FileInfo fi = new FileInfo(filename);
            if (fi.Exists)
            {
                fi.Delete();
            }
            else
            {
                SendStatus(requestId, SftpStatusType.SSH_FX_FAILURE);
            }

        }

        private void HandleStat(SshDataWorker reader)
        {
            uint requestId = reader.ReadUInt32();
            var path = reader.ReadString(Encoding.UTF8);
            SendAttributes(requestId, path, true);
        }

        private void HandleFStat(SshDataWorker reader)
        {
            var requestId = reader.ReadUInt32();
            var handle = reader.ReadString(Encoding.UTF8);
            if (HandleToPathDictionary.ContainsKey(handle))
            {
                var path = HandleToPathDictionary[handle];
                SendAttributes(requestId, path, true);
            }
            else
            {
                SendStatus(requestId, SftpStatusType.SSH_FX_NO_SUCH_FILE);
            }

        }

        private void HandleClose(SshDataWorker reader)
        {
            var requestId = reader.ReadUInt32();
            var handle = reader.ReadString(Encoding.UTF8);

            if (HandleToPathDictionary.ContainsKey(handle))
            {
                HandleToPathDictionary.Remove(handle);
                if (HandleToFileStreamDictionary.ContainsKey(handle))
                {
                    var stream = HandleToFileStreamDictionary[handle];
                    try
                    {
                        stream.Close();
                        stream.Dispose();
                    }
                    catch { }
                    HandleToFileStreamDictionary.Remove(handle);
                }
            }

            SendStatus(requestId, SftpStatusType.SSH_FX_OK);
        }

       /// <summary>
       /// The function reads the request-id, handle, offset and length from the packet and then reads
       /// the file from the offset and length specified 
       /// </summary>
       /// <param name="SshDataWorker">This is a class that I wrote to help with reading and writing SSH
       /// packets. </param>
       /// <returns>
       /// SendStatus method will be called on EOF or on error otherwise the method will will send data from 
       /// the file being read to the SSH channel
       /// </returns>
        private void HandleReadFile(SshDataWorker reader)
        {
            SshDataWorker writer = new SshDataWorker();
            var requestId = reader.ReadUInt32(); //uint32 request-id
            var handle = reader.ReadString(Encoding.UTF8);
            if (HandleToPathDictionary.ContainsKey(handle))
            {
                var fs = HandleToFileStreamDictionary[handle];
                var offset = (long)reader.ReadUInt64();
                var length = (int)reader.ReadUInt32();
                var buffer = new byte[length];
                if (fs.Length - offset < 0) // EOF already reached
                {
                    SendStatus((uint)requestId, SftpStatusType.SSH_FX_EOF);
                    return;
                }
                writer.Write((byte)RequestPacketType.SSH_FXP_DATA);
                writer.Write((uint)requestId);

                if (fs.Length - offset < length)
                {
                    buffer = new byte[fs.Length - offset];
                }
                fs.Seek(offset, SeekOrigin.Begin);
                fs.Read(buffer);
                writer.WriteBinary(buffer);
                SendPacket(writer.ToByteArray());
            }
            else
            {
                SendStatus((uint)requestId, SftpStatusType.SSH_FX_OP_UNSUPPORTED);
                return;
                // send invalid handle: SSH_FX_INVALID_HANDLE
            }
        }
 
        /// <summary>
        /// It reads the file handle, the offset from the beginning of the file, and the data to write,
        /// and then writes the data to the file at the specified offset
        /// </summary>
        /// <param name="SshDataWorker">This is a class that I wrote to help me read and write data to
        /// the SSH stream.</param>
        /// <returns>
        /// The method will return status to the SSH client using the SendStatus method.
        /// </returns>        
        private void HandleWriteFile(SshDataWorker reader)
        {
            SshDataWorker writer = new SshDataWorker();
            var requestId = reader.ReadUInt32(); //uint32 request-id
            var handle = reader.ReadString(Encoding.UTF8);
            if (HandleToPathDictionary.ContainsKey(handle))
            {
                if (!HandleToFileStreamDictionary.ContainsKey(handle))
                {
                    var newfs = new FileStream(UserRootDirectory + HandleToPathDictionary[handle], FileMode.OpenOrCreate);
                    HandleToFileStreamDictionary.Add(handle, newfs);
                }
                var fs = HandleToFileStreamDictionary[handle];
                var offsetfromfileBeginning = (long)reader.ReadUInt64();

                var buffer = reader.ReadBinary();

                if (fs.CanWrite && fs.CanSeek)
                {
                    fs.Seek(offsetfromfileBeginning, SeekOrigin.Begin);
                    fs.Write(buffer, 0, buffer.Length);

                    SendStatus(requestId, SftpStatusType.SSH_FX_OK);
                }
                else if (!fs.CanWrite)
                    SendStatus(requestId, SftpStatusType.SSH_FX_PERMISSION_DENIED);
                else
                    SendStatus(requestId, SftpStatusType.SSH_FX_OP_UNSUPPORTED);

            }
            else
            {
                SendStatus((uint)requestId, SftpStatusType.SSH_FX_OP_UNSUPPORTED);
                return;
            }
        }

        private void HandleOpenDir(SshDataWorker reader)
        {
            var writer = new SshDataWorker();
            var requestId = reader.ReadUInt32();
            var path = reader.ReadString(Encoding.UTF8);
            var handle = GenerateHandle();
            var absolutepath = UserRootDirectory + path;

            System.IO.DirectoryInfo di = new System.IO.DirectoryInfo(absolutepath);
            if (!di.Exists)
                SendStatus(requestId, SftpStatusType.SSH_FX_NO_SUCH_FILE);
            else
            {
                HandleToPathDictionary.Add(handle, path);
                HandleToPathDirList.Add(handle, ListDir(path));

                writer.Write((byte)RequestPacketType.SSH_FXP_HANDLE);
                writer.Write((uint)requestId);
                writer.Write(handle, Encoding.UTF8);
                SendPacket(writer.ToByteArray());
            }
        }

        
        private static string GenerateHandle()
        {
            return Guid.NewGuid().ToString().Replace("-", "");
        }

        private void HandleFileOpen(SshDataWorker reader)
        {
            SshDataWorker writer = new SshDataWorker();

            var requestId = reader.ReadUInt32(); //uint32 request-id
            var path = reader.ReadString(Encoding.UTF8); // //string filename [UTF-8]
            string handle = GenerateHandle();
            HandleToPathDictionary.Add(handle, path);

            var desired_access = reader.ReadUInt32();
            var flags = reader.ReadUInt32();

            //uint32 desired-access
            var write = desired_access & (uint)FileSystemOperation.Write;
            var read = desired_access & (uint)FileSystemOperation.Read;
            var create = desired_access & (uint)FileSystemOperation.Create;
            //uint32 flags
            //ATTRS  attrs
            var absolutepath = UserRootDirectory + path;
            System.IO.FileInfo fi = new System.IO.FileInfo(absolutepath);

            if (read > 0 && write == 0 && create == 0)
            {
                try
                {

                    var fs = fi.OpenRead();
                    HandleToFileStreamDictionary.Add(handle, fs);
                }
                catch
                {
                    SendStatus(requestId, SftpStatusType.SSH_FX_PERMISSION_DENIED);
                }
            }

            writer.Write((byte)RequestPacketType.SSH_FXP_HANDLE);
            writer.Write((uint)requestId);
            writer.Write(handle, Encoding.UTF8);
            // returns SSH_FXP_HANDLE on success or a SSH_FXP_STATUS message on fail

            SendPacket(writer.ToByteArray());
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="path"></param>
        /// <returns>Dictionary with relativepath, FileInfo object</returns>
        private Dictionary<string, FileInfo> ListDir(string path)
        {
            var absolutepath = UserRootDirectory + path;

            DirectoryInfo diRoot = new DirectoryInfo(UserRootDirectory + "/");
            DirectoryInfo di = new DirectoryInfo(absolutepath);
            absolutepath = di.FullName.Replace(UserRootDirectory, "/").Replace("\\", "/").Replace("//", "/");

            if (diRoot.Parent?.FullName == di.FullName || diRoot.Parent?.Parent?.FullName == di.FullName)
            {
                di = new DirectoryInfo(UserRootDirectory);
            }


            var foundfilesAndDirs = new Dictionary<string, FileInfo>();
            var allfiles = di.GetFiles();

            foreach (var file in allfiles)
            {
                foundfilesAndDirs.Add(file.Name, new FileInfo(file.FullName));
            }


            foreach(var dir in  di.GetDirectories())
            {
                foundfilesAndDirs.Add(dir.Name, new FileInfo(dir.FullName));
            }


            if (diRoot.FullName != di.FullName && path != "/" && !string.IsNullOrWhiteSpace(path))
            {
                foundfilesAndDirs.Add("..", new FileInfo(di.Parent.FullName));  // if not on root level, add parent too

            }

            return foundfilesAndDirs;
        }

        private string HandleReadDir(SshDataWorker reader)
        {
            var requestId = reader.ReadUInt32();
            var handle = reader.ReadString(Encoding.UTF8);
            var writer = new SshDataWorker();

            if (HandleToPathDictionary.ContainsKey(handle)) // remove after handle is used first time
            {
                
                var filesanddirs  = HandleToPathDirList[handle];

                var firstitem = filesanddirs.Keys.FirstOrDefault();

                if (firstitem != null)
                {
                    ReturnReadDir(filesanddirs[firstitem].FullName, requestId, firstitem == "..");
                    filesanddirs.Remove(firstitem); // remove first item from "queue" with dir-items to list
                }
                else
                {
                    HandleToPathDictionary.Remove(handle); // remove will return EOF next time
                    SendStatus(requestId, SftpStatusType.SSH_FX_EOF);
                }

            }
            else
            {
                // return SSH_FXP_STATUS indicating SSH_FX_EOF  when all files have been listed
                SendStatus(requestId, SftpStatusType.SSH_FX_EOF);
            }

            return handle;
        }

        private void ReturnReadDir(string absolutepath, uint requestId, bool isParent)
        {
            var writer = new SshDataWorker();

            // returns SSH_FXP_NAME or SSH_FXP_STATUS with SSH_FX_EOF 
            writer.Write((byte)RequestPacketType.SSH_FXP_NAME);
            writer.Write((uint)requestId);
            writer.Write((uint)1); // one file/directory at a time

            _logger.LogInformation($"Reading path {absolutepath} RequestId: {requestId}");

            FileAttributes attr = File.GetAttributes(absolutepath);
            if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
            {
                // this is a directory
                var dir = new DirectoryInfo(absolutepath);
                writer.Write(GetDirectoryWithAttributes(dir, isParent));
            }
            else
            {
                var fi = new FileInfo(absolutepath);
                writer.Write(GetFileWithAttributes(fi));
                // this is a file
            }

            SendPacket(writer.ToByteArray());
        }

        private byte[] GetDirectoryWithAttributes(DirectoryInfo dir, bool isParent)
        {
            SshDataWorker writer = new SshDataWorker();
            if (isParent)
                writer.Write("..", Encoding.UTF8);
            else
                writer.Write(dir.Name, Encoding.UTF8);

            if (isParent)
                writer.Write($"drwxr-xr-x   1 foo     foo        Mar 25 14:29 " + "..", Encoding.UTF8);
            else
                writer.Write($"drwxr-xr-x   1 foo     foo        Mar 25 14:29 " + dir.Name, Encoding.UTF8);

            writer.Write(GetAttributes(dir.FullName, true));


            return writer.ToByteArray();
        }

        private void HandleRealPath(SshDataWorker reader, bool ignoreReadingPath)
        {
            SshDataWorker writer = new SshDataWorker();
            var requestId = reader.ReadUInt32();
            var path = "/";
            if (!ignoreReadingPath)
            {
                path = (reader.ReadString(Encoding.UTF8)).Trim();

                // return current dir for absolutepath
                if (path == "" || path == "." || path == "/.")
                    path = "/"; // replace with current filepath
            }
            WritePathAttributes(writer, requestId, path);
        }

        private void WritePathAttributes(SshDataWorker writer, uint requestId, string path)
        {
            writer.Write((byte)RequestPacketType.SSH_FXP_NAME);
            writer.Write((uint)requestId);
            writer.Write((uint)1); // always count = 1 for realpath


            if (path.Length < 150)
                _logger.LogInformation($"Reading path {path}");

            writer.Write(path, Encoding.UTF8);
            //// Dummy dir for SSH_FXP_REALPATH request
            writer.Write(@"drwxr-xr-x   1 foo     foo      0 Mar 25 14:29 " + path, Encoding.UTF8);
            writer.Write(GetAttributes(path, true));

            SendPacket(writer.ToByteArray());
        }

        private void HandleInit(SshDataWorker reader)
        {
            if (sftpversion > 0)
            {
                _logger.LogInformation($"Client already initialized, calling HandleRealPath with a file list for root path");

                HandleRealPath(reader, true);
                cwdInitialized = true;
            }
            else
            {
                SshDataWorker writer = new SshDataWorker();
                var sftpclientversion = reader.ReadUInt32();
                writer.Write((byte)RequestPacketType.SSH_FXP_VERSION);
                var version = Math.Min(3, sftpclientversion);

                writer.Write((uint)version); // SFTP protocol version
                sftpversion = Convert.ToInt32(version);
                _logger.LogInformation($"Init with client version: {sftpversion}");
                SendPacket(writer.ToByteArray());
            }
        }

        private void HandleVersion(SshDataWorker reader)
        {
           
                //SshDataWorker writer = new SshDataWorker();
            //    var sftpclientversion = reader.ReadUInt32();
            //_logger.LogInformation($"Version with client version: {sftpclientversion}");


            //writer.Write((byte)RequestPacketType.SSH_FXP_INIT);
            //var version = Math.Min(3, sftpclientversion);

            //writer.Write((uint)version); // SFTP protocol version
            //sftpversion = Convert.ToInt32(version);
            //_logger.LogInformation($"Version with client version: {sftpversion}");
            //SendPacket(writer.ToByteArray());

        }

        private void SendAttributes(uint requestId, string path, bool isDirectory)
        {
            SshDataWorker writer = new SshDataWorker();
            writer.Write((byte)RequestPacketType.SSH_FXP_ATTRS);
            writer.Write(requestId);
            writer.Write(GetAttributes(path, isDirectory));
            SendPacket(writer.ToByteArray());
        }


        private byte[] GetFileWithAttributes(System.IO.FileInfo file)
        {
            SshDataWorker writer = new SshDataWorker();
            writer.Write(file.Name, Encoding.UTF8);
            writer.Write($"-rwxr-xr-x   1 foo     foo      {file.Length} Mar 25 14:29 " + file.Name, Encoding.UTF8);
            writer.Write(GetAttributes(file.FullName, false));

            return writer.ToByteArray();
        }
        private byte[] GetAttributes(string path, bool isDirectory)
        {
            SshDataWorker writer = new SshDataWorker();
            if (isDirectory)
            {
                System.IO.DirectoryInfo dirinfo = new DirectoryInfo(path);
                writer.Write(uint.MinValue); // flags
                writer.Write(ulong.MinValue); // size
                writer.Write(uint.MinValue); // uid
                writer.Write(uint.MinValue); // gid
                writer.Write(uint.MinValue); // permissions
                writer.Write(GetUnixFileTime(DateTime.Now)); //atime   
                writer.Write(GetUnixFileTime(DateTime.Now)); //mtime
                writer.Write((uint)0); // extended_count
                                       //string   extended_type blank
                                       //string   extended_data blank
            }
            else
            {
                System.IO.FileInfo fileinfo = new FileInfo(path);
                writer.Write(uint.MaxValue); // flags
                writer.Write((ulong)fileinfo.Length); // size
                writer.Write(uint.MaxValue); // uid
                writer.Write(uint.MaxValue); // gid
                writer.Write(uint.MaxValue); // permissions
                writer.Write(GetUnixFileTime(DateTime.Now)); //atime   
                writer.Write(GetUnixFileTime(DateTime.Now)); //mtime
                writer.Write((uint)0); // extended_count
                                       //string   extended_type blank
                                       //string   extended_data blank
            }

            return writer.ToByteArray();

        }

        private void SendStatus(uint requestId, SftpStatusType status)
        {
            SshDataWorker writer = new SshDataWorker();
            writer.Write((byte)RequestPacketType.SSH_FXP_STATUS);
            writer.Write(requestId);
            writer.Write((uint)status); // status code
                                        //writer.Write("", Encoding.UTF8);
                                        //writer.Write("", Encoding.UTF8);
            SendPacket(writer.ToByteArray());
        }

        /// <summary>
        /// They are represented as seconds from Jan 1, 1970 in UTC.
        /// </summary>
        /// <param name="now"></param>
        /// <returns></returns>
        private uint GetUnixFileTime(DateTime time)
        {
            TimeSpan diff = time.ToUniversalTime() - DateTime.UnixEpoch;
            return (uint)Math.Floor(diff.TotalSeconds);

        }

        /// <summary>
        /// calculates and add packet length uint to the beginning of the packet
        /// </summary>
        /// <param name="data"></param>
        internal void SendPacket(byte[] data)
        {
            var packettosend = data.ToList();
            var length = packettosend.Count();
            SshDataWorker packetlengthwriter = new SshDataWorker();
            packetlengthwriter.Write((uint)length);
            packettosend.InsertRange(0, packetlengthwriter.ToByteArray());

            if (OnOutput != null)
                OnOutput(this, packettosend);
        }

        internal void Send(byte[] data)
        {

            if (OnOutput != null)
                OnOutput(this, data);
        }


    }
}
