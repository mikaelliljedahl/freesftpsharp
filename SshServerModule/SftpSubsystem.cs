using FxSsh;
using FxSsh.Messages.Connection;
using FxSsh.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FxSsh.SshServerModule
{

    public class SftpSubsystem
    {

        private ILogger _logger;
        private uint channel;
        internal EventHandler<ICollection<byte>> OnOutput;

        internal EventHandler OnClose;
        Dictionary<string, string> HandleToPathDictionary;

        public SftpSubsystem(ILogger logger, uint channel)
        {
            this._logger = logger;
            this.channel = channel;

            HandleToPathDictionary = new Dictionary<string, string>();
        }

        internal void OnInput(byte[] ee)
        {
            var input = Encoding.ASCII.GetString(ee);
           
            //        uint32 length
            //byte type
            //byte[length - 1] data payload
            SshDataWorker reader = new SshDataWorker(ee);
            SshDataWorker writer = new SshDataWorker();

            if (reader.DataAvailable >= 5)
            {
                var msglength = reader.ReadUInt32();
                var msgtype = (RequestPacketType)(int)reader.ReadByte();

                uint requestId = 0;
                string path = "";
                string handle = Guid.NewGuid().ToString().Replace("-","");

                switch (msgtype)
                {
                    case RequestPacketType.SSH_FXP_INIT:
                        var sftpclientversion = reader.ReadUInt32();
                        writer.Write((byte)RequestPacketType.SSH_FXP_VERSION);
                        var version = Math.Max(3, sftpclientversion);
                        writer.Write((uint)version); // SFTP protocol version
                        SendPacket(writer.ToByteArray());
                        break;

                    case RequestPacketType.SSH_FXP_REALPATH:

                        requestId = reader.ReadUInt32();
                        path = reader.ReadString(Encoding.UTF8);
                        // List files in root directory for this user
                        // foreach file create a response message
                        if (path == ".")
                            path = "/"; // replace with current filepath

                        writer.Write((byte)RequestPacketType.SSH_FXP_NAME);
                        writer.Write((uint)requestId);
                        writer.Write((uint)1);
                        // Dummy file for SSH_FXP_REALPATH request
                        writer.Write(path, Encoding.UTF8);
                        writer.Write(@"-rwxr-xr-x   1 mjos     staff      348911 Mar 25 14:29 "+ path, Encoding.UTF8);

                        writer.Write((uint)requestId);
                        writer.Write(uint.MaxValue); // flags
                        writer.Write((ulong)0); // size
                        writer.Write(uint.MaxValue); // uid
                        writer.Write(uint.MaxValue); // gid
                        writer.Write(uint.MaxValue); // permissions
                        writer.Write(GetUnixFileTime(DateTime.Now)); //atime   
                        writer.Write(GetUnixFileTime(DateTime.Now)); //mtime
                        writer.Write((uint)0); // extended_count
                                               //string   extended_type blank
                                               //string   extended_data blank


                        SendPacket(writer.ToByteArray());

                        break;

                    case RequestPacketType.SSH_FXP_READDIR:
                        requestId = reader.ReadUInt32();
                        handle = reader.ReadString(Encoding.UTF8);

                        if (HandleToPathDictionary.ContainsKey(handle)) // remove - this is just for testing
                        {

                            // returns SSH_FXP_NAME or SSH_FXP_STATUS with SSH_FX_EOF 
                            writer.Write((byte)RequestPacketType.SSH_FXP_NAME);
                            writer.Write((uint)requestId);
                            writer.Write((uint)1); // 1 file item at a time
                            // Dummy file for test 
                            writer.Write(path, Encoding.UTF8);
                            writer.Write(@"-rwxr-xr-x   1 mjos     staff      348911 Mar 25 14:29 " + path, Encoding.UTF8);

                            writer.Write((uint)requestId);
                            writer.Write(uint.MaxValue); // flags
                            writer.Write((ulong)0); // size
                            writer.Write(uint.MaxValue); // uid
                            writer.Write(uint.MaxValue); // gid
                            writer.Write(uint.MaxValue); // permissions
                            writer.Write(GetUnixFileTime(DateTime.Now)); //atime   
                            writer.Write(GetUnixFileTime(DateTime.Now)); //mtime
                            writer.Write((uint)0); // extended_count
                                                   //string   extended_type blank
                                                   //string   extended_data blank


                            SendPacket(writer.ToByteArray());

                            HandleToPathDictionary.Remove(handle); // remove - this is just for testing

                        }
                        else
                        {
                            // return SSH_FXP_STATUS indicating SSH_FX_EOF  when all files have been listed
                            writer.Write((byte)RequestPacketType.SSH_FXP_STATUS);
                            writer.Write((uint)requestId);
                            writer.Write((uint)SftpStatusType.SSH_FX_EOF); // status code
                            //writer.Write("", Encoding.UTF8);
                            //writer.Write("", Encoding.UTF8);
                            SendPacket(writer.ToByteArray());
                        }

                        break;

                    case RequestPacketType.SSH_FXP_OPENDIR:
                        requestId = reader.ReadUInt32();
                        path = reader.ReadString(Encoding.UTF8);

                        HandleToPathDictionary.Add(handle, path);

                        writer.Write((byte)RequestPacketType.SSH_FXP_HANDLE);
                        writer.Write((uint)requestId);
                        writer.Write(handle, Encoding.UTF8);
                        // returns SSH_FXP_HANDLE on success or a SSH_FXP_STATUS message on fail

                        SendPacket(writer.ToByteArray());

                        _logger.LogInformation($"sftp command {msgtype.ToString()} request Id: \"{requestId}\". path: {path} on channel: {channel}");

                        break;

                    case RequestPacketType.SSH_FXP_STAT: // follows symbolic links
                    case RequestPacketType.SSH_FXP_LSTAT: // does not follow symbolic links
                        requestId = reader.ReadUInt32();
                        path = reader.ReadString(Encoding.UTF8);

                        SendAttributes(requestId, path);

                        break;

                    case RequestPacketType.SSH_FXP_FSTAT: // SSH_FXP_FSTAT differs from the others in that it returns status information for an open file(identified by the file handle).
                        requestId = reader.ReadUInt32();
                        handle = reader.ReadString(Encoding.UTF8);
                        if (HandleToPathDictionary.ContainsKey(handle))
                        {
                            path = HandleToPathDictionary[handle];
                            SendAttributes(requestId, path);
                        }
                        else
                        {
                            SendStatus(requestId, SftpStatusType.SSH_FX_NO_SUCH_FILE);
                        }

                        break;

                    case RequestPacketType.SSH_FXP_CLOSE:
                        requestId = reader.ReadUInt32();
                        handle = reader.ReadString(Encoding.UTF8);

                        if (HandleToPathDictionary.ContainsKey(handle))
                        {
                            HandleToPathDictionary.Remove(handle);
                        }

                        SendStatus(requestId, SftpStatusType.SSH_FX_OK);

                      

                        break;

                    default:
                        // unsupported command
                        _logger.LogWarning($"Unsupported sftp command {msgtype.ToString()} input: \"{input}\". on channel: {channel}");

                        break;
                }
            }
        }

      
        private void SendAttributes(uint requestId, string path)
        {
            SshDataWorker writer = new SshDataWorker();
            writer.Write((byte)RequestPacketType.SSH_FXP_ATTRS);
            writer.Write(requestId);

            writer.Write(GetAttributes(path));

            SendPacket(writer.ToByteArray());
        }

        private byte[] GetAttributes(string path)
        {
            SshDataWorker writer = new SshDataWorker();
            writer.Write(uint.MaxValue); // flags
            writer.Write((ulong)10); // size
            writer.Write(uint.MaxValue); // uid
            writer.Write(uint.MaxValue); // gid
            writer.Write(uint.MaxValue); // permissions
            writer.Write(GetUnixFileTime(DateTime.Now)); //atime   
            writer.Write(GetUnixFileTime(DateTime.Now)); //mtime
            writer.Write((uint)0); // extended_count
                                   //string   extended_type blank
                                   //string   extended_data blank

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


            //private static List<byte> sftpSubSystem = new List<byte>(new byte[] { 0, 0, 0, 4, 115, 102, 116, 112 });

            //// IsSftpRequest checks whether a given ssh.Request is for sftp.
            //public static bool IsSftpRequest(sshRequest _addr_req)
            //{
            //    ref ssh.Request req = ref _addr_req.val;

            //    return req.Type == "subsystem" && bytes.Equal(sftpSubSystem, req.Payload);
            //}

            //private static byte initReply = new slice<byte>(new byte[] { 0, 0, 0, 5, ssh_FXP_VERSION, 0, 0, 0, 3 });

            //// ServeChannel serves a ssh.Channel with the given FileSystem.
            //public static error ServeChannel(ssh.Channel c, FileSystem fs) => func((defer, _, __) =>
            //{
            //    defer(c.Close());
            //    handles h = default;
            //    h.init();
            //    defer(h.closeAll());
            //    var brd = bufio.NewReaderSize(c, 64 * 1024);
            //    error e = default!;
            //    nint plen = default;
            //    byte op = default;
            //    ref slice<byte> bs = ref heap(out ptr<slice<byte>> _addr_bs);
            //    ref uint id = ref heap(out ptr<uint> _addr_id);
            //    while (true)
            //    {
            //        if (e != null)
            //        {
            //            debug("Sending error", e);
            //            e = error.As(writeErr(c, id, e))!;
            //            if (e != null)
            //            {
            //                return error.As(e)!;
            //            }

            //        }

            //        discard(_addr_brd, plen);
            //        plen, op, e = readPacketHeader(_addr_brd);
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        plen--;
            //        debugf("CR op=%v data len=%d\n", ssh_fxp(op), plen);
            //        if (plen < 2)
            //        {
            //            return error.As(errors.New("Packet too short"))!;
            //        }
            //        // Feeding too large values to peek is ok, it just errors.
            //        bs, e = brd.Peek(plen);
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        debugf("Data %X\n", bs);
            //        var p = binp.NewParser(bs);

            //        if (op == ssh_FXP_INIT)
            //            e = error.As(wrc(c, initReply))!;
            //        else if (op == ssh_FXP_OPEN)
            //            ref @string path = ref heap(out ptr<@string> _addr_path);
            //        ref uint flags = ref heap(out ptr<uint> _addr_flags);
            //        ref Attr a = ref heap(out ptr<Attr> _addr_a);
            //        e = error.As(parseAttr(_addr_p.B32(_addr_id).B32String(_addr_path).B32(_addr_flags), _addr_a).End())!;
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        if (h.nfiles() >= maxFiles)
            //        {
            //            e = error.As(errTooManyFiles)!;
            //            continue;
            //        }

            //        File f = default;
            //        f, e = fs.OpenFile(path, flags, _addr_a);
            //        if (e != null)
            //        {
            //            continue;
            //        }

            //        e = error.As(writeHandle(c, id, h.newFile(f)))!;
            //        else if (op == ssh_FXP_CLOSE)
            //            ref @string handle = ref heap(out ptr<@string> _addr_handle);
            //        e = error.As(p.B32(_addr_id).B32String(_addr_handle).End())!;
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        h.closeHandle(handle);
            //        e = error.As(writeErr(c, id, null))!;
            //        else if (op == ssh_FXP_READ)
            //            handle = default;
            //        ref ulong offset = ref heap(out ptr<ulong> _addr_offset);
            //        ref uint length = ref heap(out ptr<uint> _addr_length);
            //        nint n = default;
            //        e = error.As(p.B32(_addr_id).B32String(_addr_handle).B64(_addr_offset).B32(_addr_length).End())!;
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        f = h.getFile(handle);
            //        if (f == null)
            //        {
            //            return error.As(errInvalidHandle)!;
            //        }

            //        if (length > 64 * 1024)
            //        {
            //            length = 64 * 1024;
            //        }

            //        bs = bytepool.Alloc(int(length));
            //        n, e = f.ReadAt(bs, int64(offset));
            //        // Handle go readers that return io.EOF and bytes at the same time.
            //        if (e == io.EOF && n > 0)
            //        {
            //            e = error.As(null)!;
            //        }

            //        if (e != null)
            //        {
            //            bytepool.Free(bs);
            //            continue;
            //        }

            //        bs = bs[(int)0..(int)n];
            //        e = error.As(wrc(c, binp.Out().B32(1 + 4 + 4 + uint32(len(bs))).Byte(ssh_FXP_DATA).B32(id).B32(uint32(len(bs))).Out()))!;
            //        if (e == null)
            //        {
            //            e = error.As(wrc(c, bs))!;
            //        }

            //        bytepool.Free(bs);
            //        else if (op == ssh_FXP_WRITE)
            //            handle = default;
            //        offset = default;
            //        length = default;
            //        p.B32(_addr_id).B32String(_addr_handle).B64(_addr_offset).B32(_addr_length);
            //        f = h.getFile(handle);
            //        if (f == null)
            //        {
            //            return error.As(errInvalidHandle)!;
            //        }

            //        bs = default;
            //        e = error.As(p.NBytesPeek(int(length), _addr_bs).End())!;
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        _, e = f.WriteAt(bs, int64(offset));
            //        e = error.As(writeErr(c, id, e))!;
            //        else if (op == ssh_FXP_LSTAT || op == ssh_FXP_STAT)
            //            path = default;
            //        a = ;
            //        e = error.As(p.B32(_addr_id).B32String(_addr_path).End())!;
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        a, e = fs.Stat(path, op == ssh_FXP_LSTAT);
            //        debug("stat/lstat", path, "=>", a, e);
            //        e = error.As(writeAttr(c, id, _addr_a, e))!;
            //        else if (op == ssh_FXP_FSTAT)
            //            handle = default;
            //        a = ;
            //        e = error.As(p.B32(_addr_id).B32String(_addr_handle).End())!;
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        f = h.getFile(handle);
            //        if (f == null)
            //        {
            //            return error.As(errInvalidHandle)!;
            //        }

            //        a, e = f.FStat();
            //        e = error.As(writeAttr(c, id, _addr_a, e))!;
            //        else if (op == ssh_FXP_SETSTAT)
            //            path = default;
            //        a = default;
            //        e = error.As(parseAttr(_addr_p.B32(_addr_id).B32String(_addr_path), _addr_a).End())!;
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        e = error.As(writeErr(c, id, fs.SetStat(path, _addr_a)))!;
            //        else if (op == ssh_FXP_FSETSTAT)
            //            handle = default;
            //        a = default;
            //        e = error.As(parseAttr(_addr_p.B32(_addr_id).B32String(_addr_handle), _addr_a).End())!;
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        f = h.getFile(handle);
            //        if (f == null)
            //        {
            //            return error.As(errInvalidHandle)!;
            //        }

            //        e = error.As(writeErr(c, id, f.FSetStat(_addr_a)))!;
            //        else if (op == ssh_FXP_OPENDIR)
            //            path = default;
            //        Dir dh = default;
            //        e = error.As(p.B32(_addr_id).B32String(_addr_path).End())!;
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        dh, e = fs.OpenDir(path);
            //        debug("opendir", id, path, "=>", dh, e);
            //        if (e != null)
            //        {
            //            continue;
            //        }

            //        e = error.As(writeHandle(c, id, h.newDir(dh)))!;
            //        else if (op == ssh_FXP_READDIR)
            //            handle = default;
            //        e = error.As(p.B32(_addr_id).B32String(_addr_handle).End())!;
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        f = h.getDir(handle);
            //        if (f == null)
            //        {
            //            return error.As(errInvalidHandle)!;
            //        }

            //        slice<NamedAttr> fis = default;
            //        fis, e = f.Readdir(1024);
            //        debug("readdir", id, handle, fis, e);
            //        if (e != null)
            //        {
            //            continue;
            //        }

            //        ref binp.Len l = ref heap(out ptr<binp.Len> _addr_l);
            //        var o = binp.Out().LenB32(_addr_l).LenStart(_addr_l).Byte(ssh_FXP_NAME).B32(id).B32(uint32(len(fis)));
            //        foreach (var (_, fi) in fis)
            //        {
            //            n = fi.Name;
            //            o.B32String(n).B32String(readdirLongName(_addr_fi)).B32(fi.Flags);
            //            if (fi.Flags & ATTR_SIZE != 0)
            //            {
            //                o.B64(uint64(fi.Size));
            //            }

            //            if (fi.Flags & ATTR_UIDGID != 0)
            //            {
            //                o.B32(fi.Uid).B32(fi.Gid);
            //            }

            //            if (fi.Flags & ATTR_MODE != 0)
            //            {
            //                o.B32(fileModeToSftp(fi.Mode));
            //            }

            //            if (fi.Flags & ATTR_TIME != 0)
            //            {
            //                outTimes(_addr_o, _addr_fi.Attr);
            //            }

            //        }
            //        o.LenDone(_addr_l);
            //        e = error.As(wrc(c, o.Out()))!;
            //        else if (op == ssh_FXP_REMOVE)
            //            path = default;
            //        e = error.As(p.B32(_addr_id).B32String(_addr_path).End())!;
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        e = error.As(writeErr(c, id, fs.Remove(path)))!;
            //        else if (op == ssh_FXP_MKDIR)
            //            path = default;
            //        a = default;
            //        p = p.B32(_addr_id).B32String(_addr_path);
            //        e = error.As(parseAttr(_addr_p, _addr_a).End())!;
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        e = error.As(writeErr(c, id, fs.Mkdir(path, _addr_a)))!;
            //        else if (op == ssh_FXP_RMDIR)
            //            path = default;
            //        e = error.As(p.B32(_addr_id).B32String(_addr_path).End())!;
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //        e = error.As(writeErr(c, id, fs.Rmdir(path)))!;
            //        else if (op == ssh_FXP_REALPATH)
            //            path = default; @string newpath = default;

            //        p.B32(_addr_id).B32String(_addr_path).End();
            //        newpath, e = fs.RealPath(path);
            //        debug("realpath: mapping", path, "=>", newpath, e);
            //        e = error.As(writeNameOnly(c, id, newpath, e))!;
            //        else if (op == ssh_FXP_RENAME)
            //            debug("FIXME RENAME NOT SUPPORTED");
            //        e = error.As(writeFail(c, id))!; // FIXME
            //        else if (op == ssh_FXP_READLINK)
            //            path = default;
            //        e = error.As(p.B32(_addr_id).B32String(_addr_path).End())!;
            //        path, e = fs.ReadLink(path);
            //        e = error.As(writeNameOnly(c, id, path, e))!;
            //        else if (op == ssh_FXP_SYMLINK)
            //            debug("FIXME SYMLINK NOT SUPPORTED");
            //        e = error.As(writeFail(c, id))!; // FIXME
            //        if (e != null)
            //        {
            //            return error.As(e)!;
            //        }

            //    }


            //});

            //private static var errInvalidHandle = errors.New("Client supplied an invalid handle");
            //private static var errTooManyFiles = errors.New("Too many files");

            //private static readonly nuint maxFiles = 0x100;



            //private static (nint, byte, error) readPacketHeader(ptr<bufio.Reader> _addr_rd)
            //{
            //    nint _p0 = default;
            //    byte _p0 = default;
            //    error _p0 = default!;
            //    ref bufio.Reader rd = ref _addr_rd.val;

            //    var bs = make_slice<byte>(5);
            //    var (_, e) = io.ReadFull(rd, bs);
            //    if (e != null)
            //    {
            //        return (0, 0, error.As(e)!);
            //    }

            //    return (int(binary.BigEndian.Uint32(bs)), bs[4], error.As(null!)!);

            //}

            //private static ptr<binp.Parser> parseAttr(ptr<binp.Parser> _addr_p, ptr<Attr> _addr_a)
            //{
            //    ref binp.Parser p = ref _addr_p.val;
            //    ref Attr a = ref _addr_a.val;

            //    p = p.B32(_addr_a.Flags);
            //    if (a.Flags & ssh_FILEXFER_ATTR_SIZE != 0)
            //    {
            //        p = p.B64(_addr_a.Size);
            //    }

            //    if (a.Flags & ssh_FILEXFER_ATTR_UIDGID != 0)
            //    {
            //        p = p.B32(_addr_a.Uid).B32(_addr_a.Gid);
            //    }

            //    if (a.Flags & ssh_FILEXFER_ATTR_PERMISSIONS != 0)
            //    {
            //        ref uint mode = ref heap(out ptr<uint> _addr_mode);
            //        p = p.B32(_addr_mode);
            //        a.Mode = sftpToFileMode(mode);
            //    }

            //    if (a.Flags & ssh_FILEXFER_ATTR_ACMODTIME != 0)
            //    {
            //        p = inTimes(_addr_p, _addr_a);
            //    }

            //    if (a.Flags & ssh_FILEXFER_ATTR_EXTENDED != 0)
            //    {
            //        ref uint count = ref heap(out ptr<uint> _addr_count);
            //        p = p.B32(_addr_count);
            //        if (count > 0xFF)
            //        {
            //            return _addr_null!;
            //        }

            //        var ss = make_slice<@string>(2 * int(count));
            //        for (nint i = 0; i < int(count); i++)
            //        {
            //            ref @string k = ref heap(out ptr<@string> _addr_k); ref @string v = ref heap(out ptr<@string> _addr_v);

            //            p = p.B32String(_addr_k).B32String(_addr_v);
            //            ss[2 * i + 0] = k;
            //            ss[2 * i + 1] = v;
            //        }

            //        a.Extended = ss;

            //    }

            //    return _addr_p!;

            //}

            //private static error writeAttr(ssh.Channel c, uint id, ptr<Attr> _addr_a, error e)
            //{
            //    ref Attr a = ref _addr_a.val;

            //    if (e != null)
            //    {
            //        return error.As(writeErr(c, id, e))!;
            //    }

            //    ref binp.Len l = ref heap(out ptr<binp.Len> _addr_l);
            //    var o = binp.Out().LenB32(_addr_l).LenStart(_addr_l).Byte(ssh_FXP_ATTRS).B32(id).B32(a.Flags);
            //    if (a.Flags & ssh_FILEXFER_ATTR_SIZE != 0)
            //    {
            //        o = o.B64(a.Size);
            //    }

            //    if (a.Flags & ssh_FILEXFER_ATTR_UIDGID != 0)
            //    {
            //        o = o.B32(a.Uid).B32(a.Gid);
            //    }

            //    if (a.Flags & ssh_FILEXFER_ATTR_PERMISSIONS != 0)
            //    {
            //        o = o.B32(fileModeToSftp(a.Mode));
            //    }

            //    if (a.Flags & ssh_FILEXFER_ATTR_ACMODTIME != 0)
            //    {
            //        outTimes(_addr_o, _addr_a);
            //    }

            //    if (a.Flags & ssh_FILEXFER_ATTR_EXTENDED != 0)
            //    {
            //        var count = uint32(len(a.Extended) / 2);
            //        o = o.B32(count);
            //        foreach (var (_, s) in a.Extended)
            //        {
            //            o = o.B32String(s);
            //        }

            //    }

            //    o.LenDone(_addr_l);
            //    return error.As(wrc(c, o.Out()))!;

            //}

            //private static error writeNameOnly(ssh.Channel c, uint id, @string path, error e)
            //{
            //    if (e != null)
            //    {
            //        return error.As(writeErr(c, id, e))!;
            //    }

            //    ref binp.Len l = ref heap(out ptr<binp.Len> _addr_l);
            //    var o = binp.Out().LenB32(_addr_l).LenStart(_addr_l).Byte(ssh_FXP_NAME).B32(id).B32(1);
            //    o.B32String(path).B32String(path).B32(0);
            //    o.LenDone(_addr_l);
            //    return error.As(wrc(c, o.Out()))!;

            //}

            //private static byte failTmpl = new slice<byte>(new byte[] { 0, 0, 0, 1 + 4 + 4 + 4 + 4, ssh_FXP_STATUS, 0, 0, 0, 0, 0, 0, 0, ssh_FX_FAILURE, 0, 0, 0, 0, 0, 0, 0, 0 });

            //private static error writeFail(ssh.Channel c, uint id)
            //{
            //    var bs = make_slice<byte>(len(failTmpl));
            //    copy(bs, failTmpl);
            //    binary.BigEndian.PutUint32(bs[(int)5..], id);
            //    return error.As(wrc(c, bs))!;
            //}

            //private static error writeErr(ssh.Channel c, uint id, error err)
            //{
            //    var bs = make_slice<byte>(len(failTmpl));
            //    copy(bs, failTmpl);
            //    binary.BigEndian.PutUint32(bs[(int)5..], id);
            //    ssh_fx code = default;

            //    if (err == null)
            //        code = ssh_FX_OK;
            //    else if (err == io.EOF)
            //        code = ssh_FX_EOF;
            //    else if (os.IsPermission(err))
            //        code = ssh_FX_PERMISSION_DENIED;
            //    else if (os.IsNotExist(err))
            //        code = ssh_FX_NO_SUCH_FILE;
            //    else
            //        code = ssh_FX_FAILURE;
            //    debug("Sending sftp error code", code);
            //    bs[12] = byte(code);
            //    return error.As(wrc(c, bs))!;

            //}

            //private static error writeHandle(ssh.Channel c, uint id, @string handle)
            //{
            //    return error.As(wrc(c, binp.OutCap(4 + 9 + len(handle)).B32(uint32(9 + len(handle))).B8(ssh_FXP_HANDLE).B32(id).B32String(handle).Out()))!;
            //}

            //private static error wrc(ssh.Channel c, slice<byte> bs)
            //{
            //    var (_, e) = c.Write(bs);
            //    return error.As(e)!;
            //}

            //private static error discard(ptr<bufio.Reader> _addr_brd, nint n)
            //{
            //    ref bufio.Reader brd = ref _addr_brd.val;

            //    if (n == 0)
            //    {
            //        return error.As(null!)!;
            //    }

            //    var (m, e) = io.Copy(ioutil.Discard, addr(new io.LimitedReader(R: brd, N: int64(n))));
            //    if (int(m) == n && e == io.EOF)
            //    {
            //        e = null;
            //    }

            //    return error.As(e)!;

            //}

            //private static void outTimes(ptr<binp.Printer> _addr_o, ptr<Attr> _addr_a)
            //{
            //    ref binp.Printer o = ref _addr_o.val;
            //    ref Attr a = ref _addr_a.val;

            //    o.B32(uint32(a.ATime.Unix())).B32(uint32(a.MTime.Unix()));
            //}
            //private static ptr<binp.Parser> inTimes(ptr<binp.Parser> _addr_p, ptr<Attr> _addr_a)
            //{
            //    ref binp.Parser p = ref _addr_p.val;
            //    ref Attr a = ref _addr_a.val;

            //    ref uint at = ref heap(out ptr<uint> _addr_at); ref uint mt = ref heap(out ptr<uint> _addr_mt);

            //    p = p.B32(_addr_at).B32(_addr_mt);
            //    a.ATime = time.Unix(int64(at), 0);
            //    a.MTime = time.Unix(int64(mt), 0);
            //    return _addr_p!;
            //}
    //    }
    //}
