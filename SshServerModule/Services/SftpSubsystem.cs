using FxSsh;
using FxSsh.SshServerModule;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SshServerModule.Services;


public class SftpSubsystem : IDisposable
{

    private ILogger _logger;
    private readonly IFileSystem _fileSystem;

    //private string _userRootDirectory;
    private readonly string _username;
    internal EventHandler<ICollection<byte>> OnOutput;
    int sftpversion;
    bool ProbablyOnWindowsSftpClient = false;

    //internal EventHandler OnClose;
    Dictionary<string, string> HandleToPathDictionary;
    Dictionary<string, Dictionary<string, Resource>> HandleToPathDirList;
    Dictionary<string, Stream> HandleToFileStreamDictionary;

    public SftpSubsystem(ILogger logger, IFileSystem fileSystem, string username)
    {
        _logger = logger;
        _fileSystem = fileSystem;
        //_userRootDirectory = homeDirectory;
        _username = username;

        HandleToPathDictionary = new Dictionary<string, string>();
        HandleToFileStreamDictionary = new Dictionary<string, Stream>();
        HandleToPathDirList = new Dictionary<string, Dictionary<string, Resource>>();
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
        var input = Encoding.ASCII.GetString(ee);

        //uint32 length
        //byte type
        //byte[length - 1] data payload
        SshDataWorker reader = new SshDataWorker(ee);

        if (reader.DataAvailable >= 5)
        {
            var msglength = reader.ReadUInt32();
            var msgtype = (RequestPacketType)(int)reader.ReadByte();

            if ((msgtype == RequestPacketType.SSH_FXP_INIT ||
                ProbablyOnWindowsSftpClient) &&  // special hack for windows sftp client
                 msglength > 1e6) // msglength is not sent for some reason
            {
                reader = new SshDataWorker(ee);
                msgtype = (RequestPacketType)(int)reader.ReadByte();
                msglength = (uint)ee.Length;
                ProbablyOnWindowsSftpClient = true; // only windows sftp client ignores sending msglength
            }
            else
            {
//#if DEBUG
//                _logger.LogInformation($"normal sftp command {msgtype.ToString()}, messagelength: {msglength} user: {_username}");
//#endif

            }

            switch (msgtype)
            {
                case RequestPacketType.SSH_FXP_INIT:
                    if (!ProbablyOnWindowsSftpClient)
                    {
                        HandleInit(reader);
                    }
                    else
                    {
                        var requestIdError = reader.ReadUInt32();
                        _logger.LogInformation($"sftp command {msgtype.ToString()} unsupported in this state, requestId: {requestIdError} for user: {_username}");

                        SendStatus(requestIdError, SftpStatusType.SSH_FX_OP_UNSUPPORTED);
                    }
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
                    if (msgtype > 0)
                    {
                        _logger.LogWarning($"Unsupported sftp command {msgtype.ToString()} input: \"{input}\". for user: {_username}");
                        uint requestId = reader.ReadUInt32();
                        SendStatus(requestId, SftpStatusType.SSH_FX_OP_UNSUPPORTED);
                    }
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
            try
            {
                _fileSystem.RemoveDirectory(pathtoremove);
                SendStatus(requestId, SftpStatusType.SSH_FX_OK);
                return;
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

            try
            {
                _fileSystem.MakeDirectory(newpath);
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
        
        
        if (_fileSystem.RemoveFile(filename))
            SendStatus(requestId, SftpStatusType.SSH_FX_OK);
        else
            SendStatus(requestId, SftpStatusType.SSH_FX_FAILURE);



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
            SendAttributes(requestId, path, false); // false because it is File stat, not Dir stat
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

#if DEBUG
                _logger.LogInformation($"Reading file handle {handle} with offset: {offset}, already on EOF");
#endif
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

#if DEBUG
            _logger.LogInformation($"Reading file handle {handle} with offset: {offset}, length {buffer.Length}");
#endif
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
        var requestId = reader.ReadUInt32(); //uint32 request-id
        var handle = reader.ReadString(Encoding.UTF8);
        if (HandleToPathDictionary.ContainsKey(handle))
        {
            if (!HandleToFileStreamDictionary.ContainsKey(handle))
            {
                HandleToFileStreamDictionary.Add(handle, _fileSystem.OpenStreamWrite(HandleToPathDictionary[handle]));
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
            
        }
    }

    private void HandleOpenDir(SshDataWorker reader)
    {
        var writer = new SshDataWorker();
        var requestId = reader.ReadUInt32();
        var path = reader.ReadString(Encoding.UTF8);
        var handle = GenerateHandle();
        var absolutepath = _userRootDirectory + path;

        _logger.LogInformation($"user {_username} opened dir {absolutepath}");

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
        var absolutepath = _userRootDirectory + path;
        System.IO.FileInfo fi = new System.IO.FileInfo(absolutepath);

        if (read > 0 && write == 0 && create == 0)
        {
            try
            {
                _logger.LogInformation($"Opening file {path} with handle: {handle}");

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
    private Dictionary<string, Resource> ListDir(string path)
    {
        var foundfilesAndDirs = new Dictionary<string, Resource>();
        var allfiles = _fileSystem.GetFiles(path);

        foreach (var file in allfiles)
        {
            foundfilesAndDirs.Add(file.Name, file);
        }

        foreach (var dir in _fileSystem.GetDirectories(path))
        {
            foundfilesAndDirs.Add(dir.Name, dir);
        }

        return foundfilesAndDirs;

    }

    private void HandleReadDir(SshDataWorker reader)
    {
        var requestId = reader.ReadUInt32();
        var handle = reader.ReadString(Encoding.UTF8);

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
        {
            var filedatetime = $"{dir.Parent.LastWriteTime.ToString("MMM dd HH:mm")}";
            writer.Write($"drwxr-xr-x   1 foo     bar      0 {filedatetime} ..", Encoding.UTF8);
        }
        else
        {
            var filedatetime = $"{dir.LastWriteTime.ToString("MMM dd HH:mm")}";
            writer.Write($"drwxr-xr-x   1 foo     bar      0 {filedatetime} {dir.Name}", Encoding.UTF8);
        }

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

        DateTime lastModified = _fileSystem.GetDirectoryLastModified(path);
        writer.Write(path, Encoding.UTF8);
        // Dummy dir for SSH_FXP_REALPATH request
        var filedatetime = $"{lastModified.ToString("MMM dd HH:mm")}";

        writer.Write($"drwxr-xr-x   1 foo     bar      0 {filedatetime} {path}", Encoding.UTF8);
        writer.Write(GetAttributes(path, true));

        SendPacket(writer.ToByteArray());
    }

    private void HandleInit(SshDataWorker reader)
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

        var filedatetime = $"{file.LastWriteTime.ToString("MMM dd HH:mm")}";

        //writer.Write($"-rwxrwxrwx   1 foo     foo      {file.Length} Mar 25 14:29 " + file.Name, Encoding.UTF8);
        writer.Write($"-rwxrwxrwx   1 foo     bar      {file.Length} {filedatetime} {file.Name}", Encoding.UTF8);
        writer.Write(GetAttributes(file.FullName, false));

        return writer.ToByteArray();
    }
    private byte[] GetAttributes(string path, bool isDirectory)
    {
        SshDataWorker writer = new SshDataWorker();
        if (isDirectory)
        {
            System.IO.DirectoryInfo dirinfo = new DirectoryInfo(path);
            var attributes = new SftpFileAttributes(_fileSystem.GetDirectoryLastAccessed(path), _fileSystem.GetDirectoryLastModified(path), 0, _username.GetHashCode(), _username.GetHashCode(), true, null);
            
            writer.Write((uint)12); // flags, tells the client which of the following attributes that are sent
            //writer.Write(ulong.MinValue); // size
            //writer.Write(uint.MinValue); // uid
            //writer.Write(uint.MinValue); // gid
            writer.Write(attributes.Permissions.PermissionsAsUint); // permissions
            writer.Write(GetUnixFileTime(dirinfo.LastAccessTimeUtc)); //atime   
            writer.Write(GetUnixFileTime(dirinfo.LastWriteTimeUtc)); //mtime
            writer.Write((uint)0); // extended_count
                                   //string   extended_type blank
                                   //string   extended_data blank
        }
        else
        {
            System.IO.FileInfo fileinfo = new FileInfo(path);
            var attributes = new SftpFileAttributes(_fileSystem.GetFileLastAccessed(path), _fileSystem.GetFileLastModified(path), 0, _username.GetHashCode(), _username.GetHashCode(), false, null);

            writer.Write((uint)13); // flags, tells the client which of the following attributes that are sent
            writer.Write((ulong)fileinfo.Length); // size (that is why the flags is 1 higher for files than for directories)
            //writer.Write(uint.MaxValue); // uid
            //writer.Write(uint.MaxValue); // gid
            writer.Write(attributes.Permissions.PermissionsAsUint); // permissions
            writer.Write(GetUnixFileTime(fileinfo.LastAccessTimeUtc)); //atime   
            writer.Write(GetUnixFileTime(fileinfo.LastWriteTimeUtc)); //mtime
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
