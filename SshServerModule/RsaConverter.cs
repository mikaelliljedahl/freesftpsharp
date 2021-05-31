using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;


namespace FxSsh.SshServerModule
{
    // https://gist.github.com/therightstuff/aa65356e95f8d0aae888e9f61aa29414
    public class RSAConverter
    {
        /// <summary>
        /// Import OpenSSH PEM private key string into MS RSACryptoServiceProvider
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        public static RSACryptoServiceProvider ImportPrivateKey(string pem)
        {
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }

       
        /// <summary>
        /// Import OpenSSH PEM public key string into MS RSACryptoServiceProvider
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        public static RSACryptoServiceProvider ImportPublicKey(string pem)
        {
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
            if (publicKey != null)
            {
                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);

                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
                csp.ImportParameters(rsaParams);
                return csp;
            }
            else
                return null;
        }

        public static RSACryptoServiceProvider ReadSshRsaPublicKey(byte[] key)
        {
            var keybase64 = Convert.ToBase64String(key);


            var publicKey = PublicKeyFactory.CreateKey(key);

            if (publicKey != null)
            {
                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);

                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
                csp.ImportParameters(rsaParams);
                return csp;
            }
            else
                return null;

        }

            //// https://stackoverflow.com/questions/11506891/how-to-load-the-rsa-public-key-from-file-in-c-sharp
            //public static RSACryptoServiceProvider DecodeX509PublicKey(byte[] x509key)
            //{
            //    // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            //    byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            //    byte[] seq = new byte[15];
            //    // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            //    MemoryStream mem = new MemoryStream(x509key);
            //    BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
            //    byte bt = 0;
            //    ushort twobytes = 0;

            //    try
            //    {

            //        twobytes = binr.ReadUInt16();
            //        if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
            //            binr.ReadByte();    //advance 1 byte
            //        else if (twobytes == 0x8230)
            //            binr.ReadInt16();   //advance 2 bytes
            //        else
            //            return null;

            //        seq = binr.ReadBytes(15);       //read the Sequence OID
            //        if (!CompareBytearrays(seq, SeqOID))    //make sure Sequence for OID is correct
            //            return null;

            //        twobytes = binr.ReadUInt16();
            //        if (twobytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
            //            binr.ReadByte();    //advance 1 byte
            //        else if (twobytes == 0x8203)
            //            binr.ReadInt16();   //advance 2 bytes
            //        else
            //            return null;

            //        bt = binr.ReadByte();
            //        if (bt != 0x00)     //expect null byte next
            //            return null;

            //        twobytes = binr.ReadUInt16();
            //        if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
            //            binr.ReadByte();    //advance 1 byte
            //        else if (twobytes == 0x8230)
            //            binr.ReadInt16();   //advance 2 bytes
            //        else
            //            return null;

            //        twobytes = binr.ReadUInt16();
            //        byte lowbyte = 0x00;
            //        byte highbyte = 0x00;

            //        if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
            //            lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
            //        else if (twobytes == 0x8202)
            //        {
            //            highbyte = binr.ReadByte(); //advance 2 bytes
            //            lowbyte = binr.ReadByte();
            //        }
            //        else
            //            return null;
            //        byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
            //        int modsize = BitConverter.ToInt32(modint, 0);

            //        byte firstbyte = binr.ReadByte();
            //        binr.BaseStream.Seek(-1, SeekOrigin.Current);

            //        if (firstbyte == 0x00)
            //        {   //if first byte (highest order) of modulus is zero, don't include it
            //            binr.ReadByte();    //skip this null byte
            //            modsize -= 1;   //reduce modulus buffer size by 1
            //        }

            //        byte[] modulus = binr.ReadBytes(modsize);   //read the modulus bytes

            //        if (binr.ReadByte() != 0x02)            //expect an Integer for the exponent data
            //            return null;
            //        int expbytes = (int)binr.ReadByte();        // should only need one byte for actual exponent data (for all useful values)
            //        byte[] exponent = binr.ReadBytes(expbytes);

            //        // ------- create RSACryptoServiceProvider instance and initialize with public key -----
            //        RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            //        RSAParameters RSAKeyInfo = new RSAParameters();
            //        RSAKeyInfo.Modulus = modulus;
            //        RSAKeyInfo.Exponent = exponent;
            //        RSA.ImportParameters(RSAKeyInfo);
            //        return RSA;
            //    }
            //    catch (Exception)
            //    {
            //        return null;
            //    }

            //    finally { binr.Close(); }

            //}

            //private static bool CompareBytearrays(byte[] a, byte[] b)
            //{
            //    if (a.Length != b.Length)
            //        return false;
            //    int i = 0;
            //    foreach (byte c in a)
            //    {
            //        if (c != b[i])
            //            return false;
            //        i++;
            //    }
            //    return true;
            //}

            /// <summary>
            /// Import public key byte array into MS RSACryptoServiceProvider
            /// </summary>
            /// <param name="pem"></param>
            /// <returns></returns>
            public static RSACryptoServiceProvider ImportPublicKey(byte[] publickey)
        {
            int bytesRead;
            try
            {
                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
                csp.ImportSubjectPublicKeyInfo(publickey, out bytesRead);
                return csp;
            }
            catch
            {

                var pem = System.Text.Encoding.ASCII.GetString(publickey);
                var csp = ImportPublicKey(pem);
                //csp.ImportRSAPublicKey(publickey, out bytesRead);
                return csp;
            }
           
        }

        /// <summary>
        /// Export private (including public) key from MS RSACryptoServiceProvider into OpenSSH PEM string
        /// slightly modified from https://stackoverflow.com/a/23739932/2860309
        /// </summary>
        /// <param name="csp"></param>
        /// <returns></returns>
        public static string ExportPrivateKey(RSACryptoServiceProvider csp)
        {
            StringWriter outputStream = new StringWriter();
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    EncodeIntegerBigEndian(innerWriter, parameters.D);
                    EncodeIntegerBigEndian(innerWriter, parameters.P);
                    EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN RSA PRIVATE KEY-----\n");
                // Output as Base64 with lines chopped at 64 characters
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END RSA PRIVATE KEY-----");
            }

            return outputStream.ToString();
        }

        /// <summary>
        /// Export public key from MS RSACryptoServiceProvider into OpenSSH PEM string
        /// slightly modified from https://stackoverflow.com/a/28407693
        /// </summary>
        /// <param name="csp"></param>
        /// <returns></returns>
        public static string ExportPublicKey(RSACryptoServiceProvider csp)
        {
            StringWriter outputStream = new StringWriter();
            var parameters = csp.ExportParameters(false);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN PUBLIC KEY-----\n");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END PUBLIC KEY-----");
            }

            return outputStream.ToString();
        }


        /// <summary>
        /// https://stackoverflow.com/a/23739932/2860309
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="length"></param>
        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        /// <summary>
        /// https://stackoverflow.com/a/23739932/2860309
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="value"></param>
        /// <param name="forceUnsigned"></param>
        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

    }

    //    // https://gist.github.com/canton7/5670788

    //    // Usage:
    //    // var keyLines = File.ReadAllLines(@"keyfile");
    //    // var keyBytes = System.Convert.FromBase64String(string.Join("", keyLines.Skip(1).Take(keyLines.Length - 2)));
    //    // var puttyKey = RSAConverter.FromDERPrivateKey(keyBytes).ToPuttyPrivateKey();

    //    public class RSAConverter
    //{
    //    public RSACryptoServiceProvider CryptoServiceProvider { get; private set; }
    //    public string Comment { get; set; }

    //    public RSAConverter(RSACryptoServiceProvider cryptoServiceProvider)
    //    {
    //        this.CryptoServiceProvider = cryptoServiceProvider;
    //        this.Comment = "imported-key";
    //    }

    //    public static RSAConverter FromDERPrivateKey(byte[] privateKey)
    //    {
    //        return new RSAConverter(DecodeRSAPrivateKey(privateKey));
    //    }

    //    // Adapted from http://www.jensign.com/opensslkey/opensslkey.cs
    //    public static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey)
    //    {
    //        var RSA = new RSACryptoServiceProvider();
    //        var RSAparams = new RSAParameters();

    //        // ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
    //        using (BinaryReader binr = new BinaryReader(new MemoryStream(privkey)))
    //        {
    //            byte bt = 0;
    //            ushort twobytes = 0;
    //            twobytes = binr.ReadUInt16();
    //            if (twobytes == 0x8130)    //data read as little endian order (actual data order for Sequence is 30 81)
    //                binr.ReadByte();    //advance 1 byte
    //            else if (twobytes == 0x8230)
    //                binr.ReadInt16();   //advance 2 bytes
    //            else
    //                throw new Exception("Unexpected value read");

    //            twobytes = binr.ReadUInt16();
    //            if (twobytes != 0x0102) //version number
    //                throw new Exception("Unexpected version");

    //            bt = binr.ReadByte();
    //            if (bt != 0x00)
    //                throw new Exception("Unexpected value read");

    //            //------  all private key components are Integer sequences ----
    //            RSAparams.Modulus = binr.ReadBytes(GetIntegerSize(binr));
    //            RSAparams.Exponent = binr.ReadBytes(GetIntegerSize(binr));
    //            RSAparams.D = binr.ReadBytes(GetIntegerSize(binr));
    //            RSAparams.P = binr.ReadBytes(GetIntegerSize(binr));
    //            RSAparams.Q = binr.ReadBytes(GetIntegerSize(binr));
    //            RSAparams.DP = binr.ReadBytes(GetIntegerSize(binr));
    //            RSAparams.DQ = binr.ReadBytes(GetIntegerSize(binr));
    //            RSAparams.InverseQ = binr.ReadBytes(GetIntegerSize(binr));
    //        }

    //        RSA.ImportParameters(RSAparams);
    //        return RSA;
    //    }

    //    public string ToPuttyPrivateKey()
    //    {
    //        var publicParameters = this.CryptoServiceProvider.ExportParameters(false);
    //        byte[] publicBuffer = new byte[3 + 7 + 4 + 1 + publicParameters.Exponent.Length + 4 + 1 + publicParameters.Modulus.Length + 1];

    //        using (var bw = new BinaryWriter(new MemoryStream(publicBuffer)))
    //        {
    //            bw.Write(new byte[] { 0x00, 0x00, 0x00 });
    //            bw.Write("ssh-rsa");
    //            PutPrefixed(bw, publicParameters.Exponent, true);
    //            PutPrefixed(bw, publicParameters.Modulus, true);
    //        }
    //        var publicBlob = System.Convert.ToBase64String(publicBuffer);

    //        var privateParameters = this.CryptoServiceProvider.ExportParameters(true);
    //        byte[] privateBuffer = new byte[4 + 1 + privateParameters.D.Length + 4 + 1 + privateParameters.P.Length + 4 + 1 + privateParameters.Q.Length + 4 + 1 + privateParameters.InverseQ.Length];

    //        using (var bw = new BinaryWriter(new MemoryStream(privateBuffer)))
    //        {
    //            PutPrefixed(bw, privateParameters.D, true);
    //            PutPrefixed(bw, privateParameters.P, true);
    //            PutPrefixed(bw, privateParameters.Q, true);
    //            PutPrefixed(bw, privateParameters.InverseQ, true);
    //        }
    //        var privateBlob = System.Convert.ToBase64String(privateBuffer);

    //        HMACSHA1 hmacsha1 = new HMACSHA1(new SHA1CryptoServiceProvider().ComputeHash(Encoding.ASCII.GetBytes("putty-private-key-file-mac-key")));
    //        byte[] bytesToHash = new byte[4 + 7 + 4 + 4 + 4 + this.Comment.Length + 4 + publicBuffer.Length + 4 + privateBuffer.Length];

    //        using (var bw = new BinaryWriter(new MemoryStream(bytesToHash)))
    //        {
    //            PutPrefixed(bw, Encoding.ASCII.GetBytes("ssh-rsa"));
    //            PutPrefixed(bw, Encoding.ASCII.GetBytes("none"));
    //            PutPrefixed(bw, Encoding.ASCII.GetBytes(this.Comment));
    //            PutPrefixed(bw, publicBuffer);
    //            PutPrefixed(bw, privateBuffer);
    //        }

    //        var hash = string.Join("", hmacsha1.ComputeHash(bytesToHash).Select(x => string.Format("{0:x2}", x)));

    //        var sb = new StringBuilder();
    //        sb.AppendLine("PuTTY-User-Key-File-2: ssh-rsa");
    //        sb.AppendLine("Encryption: none");
    //        sb.AppendLine("Comment: " + this.Comment);

    //        var publicLines = SpliceText(publicBlob, 64);
    //        sb.AppendLine("Public-Lines: " + publicLines.Length);
    //        foreach (var line in publicLines)
    //        {
    //            sb.AppendLine(line);
    //        }

    //        var privateLines = SpliceText(privateBlob, 64);
    //        sb.AppendLine("Private-Lines: " + privateLines.Length);
    //        foreach (var line in privateLines)
    //        {
    //            sb.AppendLine(line);
    //        }

    //        sb.AppendLine("Private-MAC: " + hash);

    //        return sb.ToString();
    //    }

    //    private static int GetIntegerSize(BinaryReader binr)
    //    {
    //        byte bt = 0;
    //        byte lowbyte = 0x00;
    //        byte highbyte = 0x00;
    //        int count = 0;
    //        bt = binr.ReadByte();
    //        if (bt != 0x02)     //expect integer
    //            throw new Exception("Expected integer");
    //        bt = binr.ReadByte();

    //        if (bt == 0x81)
    //        {
    //            count = binr.ReadByte();    // data size in next byte
    //        }
    //        else if (bt == 0x82)
    //        {
    //            highbyte = binr.ReadByte(); // data size in next 2 bytes
    //            lowbyte = binr.ReadByte();
    //            byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
    //            count = BitConverter.ToInt32(modint, 0);
    //        }
    //        else
    //        {
    //            count = bt;     // we already have the data size
    //        }

    //        while (binr.ReadByte() == 0x00)
    //        {   //remove high order zeros in data
    //            count -= 1;
    //        }

    //        binr.BaseStream.Seek(-1, SeekOrigin.Current);       //last ReadByte wasn't a removed zero, so back up a byte

    //        return count;
    //    }

    //    private static void PutPrefixed(BinaryWriter bw, byte[] bytes, bool addLeadingNull = false)
    //    {
    //        bw.Write(BitConverter.GetBytes(bytes.Length + (addLeadingNull ? 1 : 0)).Reverse().ToArray());
    //        if (addLeadingNull)
    //            bw.Write(new byte[] { 0x00 });
    //        bw.Write(bytes);
    //    }

    //    // http://stackoverflow.com/questions/7768373/c-sharp-line-break-every-n-characters
    //    private static string[] SpliceText(string text, int lineLength)
    //    {
    //        return Regex.Matches(text, ".{1," + lineLength + "}").Cast<Match>().Select(m => m.Value).ToArray();
    //    }
    //}
}
