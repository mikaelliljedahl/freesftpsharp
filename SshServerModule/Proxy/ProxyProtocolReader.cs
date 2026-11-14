#nullable enable
using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SshServerModule.Proxy
{
    /// <summary>The addresses of a PROXY protocol header.</summary>
    /// <param name="Source">The address of the client; null for a LOCAL (v2) or UNKNOWN (v1) header: then the address of the connection counts.</param>
    /// <param name="Destination">The address that the client connected to on the balancer; null with <paramref name="Source"/>.</param>
    public sealed record ProxyHeader(IPEndPoint? Source, IPEndPoint? Destination);

    /// <summary>A PROXY protocol header that is missing or not valid; the connection is refused.</summary>
    public sealed class ProxyProtocolException : Exception
    {
        public ProxyProtocolException(string message) : base(message)
        {
        }
    }

    /// <summary>
    /// Reads the PROXY protocol header (HAProxy, version 1 text and version 2 binary) at the start of a connection
    /// (issue #75), so that the server knows the real client address behind a load balancer. It reads exactly the
    /// header and never a byte after it, so the stream continues with the SSH identification of the client. A header that
    /// is not exactly valid is refused (<see cref="ProxyProtocolException"/>).
    /// </summary>
    public static class ProxyProtocolReader
    {
        /// <summary>The longest version 1 header, with CRLF.</summary>
        public const int MaxV1Length = 107;

        /// <summary>The largest version 2 address block with TLVs that is accepted (the addresses and a few TLVs).</summary>
        public const int MaxV2PayloadLength = 1024;

        private static readonly byte[] V2Signature = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];
        private static readonly byte[] V1Prefix = "PROXY "u8.ToArray();

        /// <summary>Reads the header from <paramref name="stream"/>; the stream is then at the first byte after it.</summary>
        public static async Task<ProxyHeader> ReadAsync(Stream stream, CancellationToken ct)
        {
            // Both versions are at least 12 bytes long: "PROXY UNKNOWN\r\n" has 15, a v2 header 16.
            var start = new byte[V2Signature.Length];
            await ReadExactlyAsync(stream, start, ct);

            if (start.AsSpan().SequenceEqual(V2Signature))
            {
                var fixedPart = new byte[4];
                await ReadExactlyAsync(stream, fixedPart, ct);
                var length = BinaryPrimitives.ReadUInt16BigEndian(fixedPart.AsSpan(2));
                if (length > MaxV2PayloadLength)
                    throw new ProxyProtocolException($"The PROXY v2 header is too long ({length} bytes).");
                var payload = new byte[length];
                await ReadExactlyAsync(stream, payload, ct);
                return ParseV2(fixedPart[0], fixedPart[1], payload);
            }

            if (start.AsSpan(0, V1Prefix.Length).SequenceEqual(V1Prefix))
            {
                var line = new byte[MaxV1Length];
                start.CopyTo(line, 0);
                var count = start.Length;
                while (count < 2 || line[count - 2] != '\r' || line[count - 1] != '\n')
                {
                    if (count == MaxV1Length)
                        throw new ProxyProtocolException("The PROXY v1 header is longer than 107 bytes.");
                    await ReadExactlyAsync(stream, line.AsMemory(count, 1), ct);
                    count++;
                }
                return ParseV1(line.AsSpan(0, count - 2));
            }

            throw new ProxyProtocolException("The connection does not start with a PROXY protocol header.");
        }

        /// <summary>Parses a version 1 line without its CRLF: <c>PROXY TCP4|TCP6 src dst srcport dstport</c> or <c>PROXY UNKNOWN ...</c>.</summary>
        public static ProxyHeader ParseV1(ReadOnlySpan<byte> line)
        {
            foreach (var b in line)
            {
                if (b is < 0x20 or > 0x7E)
                    throw new ProxyProtocolException("The PROXY v1 header has a character that is not allowed.");
            }
            var parts = Encoding.ASCII.GetString(line).Split(' ');
            if (parts.Length < 2 || parts[0] != "PROXY")
                throw new ProxyProtocolException("The PROXY v1 header is not valid.");
            if (parts[1] == "UNKNOWN")
                return new ProxyHeader(null, null); // the rest of the line is ignored (the specification)

            var family = parts[1] switch
            {
                "TCP4" => AddressFamily.InterNetwork,
                "TCP6" => AddressFamily.InterNetworkV6,
                _ => throw new ProxyProtocolException($"The PROXY v1 protocol '{parts[1]}' is not supported."),
            };
            if (parts.Length != 6)
                throw new ProxyProtocolException("The PROXY v1 header does not have six fields.");
            return new ProxyHeader(
                new IPEndPoint(ParseAddress(parts[2], family), ParsePort(parts[4])),
                new IPEndPoint(ParseAddress(parts[3], family), ParsePort(parts[5])));
        }

        /// <summary>Parses a version 2 header after its signature: the version and command, the family and protocol, the address block with TLVs.</summary>
        public static ProxyHeader ParseV2(byte versionCommand, byte familyProtocol, ReadOnlySpan<byte> payload)
        {
            if (versionCommand >> 4 != 2)
                throw new ProxyProtocolException("The PROXY v2 header has another version than 2.");
            var command = versionCommand & 0x0F;
            if (command == 0x0)
                return new ProxyHeader(null, null); // LOCAL: the balancer itself (a health check)
            if (command != 0x1)
                throw new ProxyProtocolException($"The PROXY v2 command {command} is not supported.");

            var family = familyProtocol >> 4;
            var protocol = familyProtocol & 0x0F;
            if (family == 0x0)
                return new ProxyHeader(null, null); // AF_UNSPEC: the address is not known
            if (protocol != 0x1)
                throw new ProxyProtocolException("The PROXY v2 header is not for a TCP (stream) connection.");

            var addressLength = family switch
            {
                0x1 => 4,
                0x2 => 16,
                _ => throw new ProxyProtocolException($"The PROXY v2 address family {family} is not supported."),
            };
            if (payload.Length < addressLength * 2 + 4)
                throw new ProxyProtocolException("The PROXY v2 address block is too short.");
            var source = new IPAddress(payload.Slice(0, addressLength));
            var destination = new IPAddress(payload.Slice(addressLength, addressLength));
            var sourcePort = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(addressLength * 2));
            var destinationPort = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(addressLength * 2 + 2));
            // The TLVs after the addresses are not needed and are skipped.
            return new ProxyHeader(new IPEndPoint(source, sourcePort), new IPEndPoint(destination, destinationPort));
        }

        private static IPAddress ParseAddress(string text, AddressFamily family)
        {
            // IPAddress.Parse also takes "1.2.3" and "0x7f.1": a v1 address is only the dotted quad or the IPv6 text.
            var valid = family == AddressFamily.InterNetwork
                ? IsDottedQuad(text)
                : text.Contains(':') && text.All(c => Uri.IsHexDigit(c) || c is ':' or '.');
            if (!valid || !IPAddress.TryParse(text, out var address) || address.AddressFamily != family)
                throw new ProxyProtocolException($"The PROXY v1 address '{text}' is not valid.");
            return address;
        }

        private static bool IsDottedQuad(string text)
        {
            var parts = text.Split('.');
            return parts.Length == 4 && parts.All(p => p.Length is >= 1 and <= 3 && p.All(char.IsAsciiDigit) && int.Parse(p, System.Globalization.CultureInfo.InvariantCulture) <= 255);
        }

        private static int ParsePort(string text)
        {
            if (text.Length is < 1 or > 5 || !text.All(char.IsAsciiDigit))
                throw new ProxyProtocolException($"The PROXY v1 port '{text}' is not valid.");
            var port = int.Parse(text, System.Globalization.CultureInfo.InvariantCulture);
            if (port > 65535)
                throw new ProxyProtocolException($"The PROXY v1 port '{text}' is not valid.");
            return port;
        }

        private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
        {
            try
            {
                await stream.ReadExactlyAsync(buffer, ct);
            }
            catch (EndOfStreamException)
            {
                throw new ProxyProtocolException("The connection ended inside the PROXY protocol header.");
            }
        }
    }
}
