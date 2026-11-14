using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SshServer.Interfaces.Authentication;

/// <summary>A key or a line that <see cref="SshPublicKey"/> refuses. The message is meant for the operator and has no key data.</summary>
public sealed class PublicKeyFormatException : FormatException
{
    public PublicKeyFormatException(string message) : base(message)
    {
    }
}

/// <summary>The keys of an <c>authorized_keys</c> text and the lines that were refused.</summary>
public sealed record PublicKeyParseResult(IReadOnlyList<PublicKeyEntry> Keys, IReadOnlyList<string> Errors);

/// <summary>
/// Reads user public keys (issue #58): OpenSSH <c>authorized_keys</c> lines (<c>type base64 [comment]</c>) and PEM public
/// keys (RSA or ECDSA). It checks the structure of the key blob (RFC 4253 section 6.6, RFC 5656 section 3.1,
/// RFC 8709 section 4) and computes the fingerprint. It needs no other key library.
/// <para>
/// Not supported, and refused with a message: <c>authorized_keys</c> options (<c>from=</c>, <c>restrict</c>, ...),
/// certificates, DSA keys, security keys (<c>sk-...</c>) and RSA keys below <see cref="MinimumRsaBits"/> bits.
/// </para>
/// </summary>
public static class SshPublicKey
{
    public const string Ed25519 = "ssh-ed25519";
    public const string Rsa = "ssh-rsa";
    public const string EcdsaNistP256 = "ecdsa-sha2-nistp256";
    public const string EcdsaNistP384 = "ecdsa-sha2-nistp384";
    public const string EcdsaNistP521 = "ecdsa-sha2-nistp521";

    /// <summary>The smallest RSA key that can be added (the old single key of a user is migrated whatever its size).</summary>
    public const int MinimumRsaBits = 2048;

    public static readonly IReadOnlyList<string> SupportedKeyTypes = [Ed25519, EcdsaNistP256, EcdsaNistP384, EcdsaNistP521, Rsa];

    /// <summary>Reads one key: an <c>authorized_keys</c> line or a PEM public key.</summary>
    /// <exception cref="PublicKeyFormatException">The text is not one supported key.</exception>
    public static PublicKeyEntry Parse(string text, PublicKeySource source, DateTime addedAtUtc)
    {
        var result = ParseAuthorizedKeys(text, source, addedAtUtc);
        if (result.Errors.Count > 0)
            throw new PublicKeyFormatException(result.Errors[0]);
        if (result.Keys.Count != 1)
            throw new PublicKeyFormatException(result.Keys.Count == 0 ? "There is no public key in the text." : "The text has more than one public key.");
        return result.Keys[0];
    }

    /// <summary>
    /// Reads the keys of an <c>authorized_keys</c> text: one key per line, empty lines and <c>#</c> comments are skipped.
    /// A text that starts with <c>-----BEGIN</c> is one PEM public key.
    /// </summary>
    public static PublicKeyParseResult ParseAuthorizedKeys(string text, PublicKeySource source, DateTime addedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(text);
        var keys = new List<PublicKeyEntry>();
        var errors = new List<string>();

        var trimmed = text.Trim();
        if (trimmed.StartsWith("-----BEGIN", StringComparison.Ordinal))
        {
            try
            {
                keys.Add(FromPem(trimmed, source, addedAtUtc));
            }
            catch (PublicKeyFormatException ex)
            {
                errors.Add(ex.Message);
            }
            return new PublicKeyParseResult(keys, errors);
        }

        var lines = text.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;
            try
            {
                keys.Add(ParseLine(line, source, addedAtUtc));
            }
            catch (PublicKeyFormatException ex)
            {
                errors.Add(lines.Length == 1 ? ex.Message : $"Line {i + 1}: {ex.Message}");
            }
        }
        return new PublicKeyParseResult(keys, errors);
    }

    /// <summary>Makes an entry from an SSH public key blob (as sent in a login request or in <c>authorized_keys</c>).</summary>
    /// <exception cref="PublicKeyFormatException">The blob is not a supported key.</exception>
    public static PublicKeyEntry FromBlob(byte[] blob, string? comment, PublicKeySource source, DateTime addedAtUtc)
        => FromBlob(blob, comment, source, addedAtUtc, checkRsaSize: true);

    /// <summary>Makes an <c>ssh-rsa</c> entry from RSA parameters (modulus and exponent).</summary>
    public static PublicKeyEntry FromRsa(RSAParameters parameters, string? comment, PublicKeySource source, DateTime addedAtUtc)
        => FromBlob(RsaBlob(parameters), comment, source, addedAtUtc, checkRsaSize: true);

    /// <summary>
    /// Converts the old single key of a user (<c>User.RsaPublicKey</c> before issue #58: a base64 CSP blob of an RSA public
    /// key) to an entry. The key size is not checked, so the user keeps the key it had.
    /// </summary>
    /// <exception cref="PublicKeyFormatException">The text is not a CSP blob of an RSA key.</exception>
    public static PublicKeyEntry FromLegacyCspBlob(string base64CspBlob, DateTime addedAtUtc)
    {
        RSAParameters parameters;
        try
        {
            using var csp = new RSACryptoServiceProvider();
            csp.ImportCspBlob(Convert.FromBase64String(base64CspBlob));
            parameters = csp.ExportParameters(false);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
        {
            throw new PublicKeyFormatException("The old public key cannot be read.");
        }
        return FromBlob(RsaBlob(parameters), "migrated key", PublicKeySource.Admin, addedAtUtc, checkRsaSize: false);
    }

    /// <summary>"SHA256:..." of a key blob, as OpenSSH shows it (base64 without padding).</summary>
    public static string Fingerprint(ReadOnlySpan<byte> blob) => "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=');

    /// <summary>The <c>authorized_keys</c> line of an entry.</summary>
    public static string ToAuthorizedKeysLine(PublicKeyEntry entry)
        => string.IsNullOrWhiteSpace(entry.Comment) ? $"{entry.KeyType} {entry.KeyBase64}" : $"{entry.KeyType} {entry.KeyBase64} {entry.Comment}";

    /// <summary>The <c>ssh-rsa</c> key blob of RSA parameters.</summary>
    public static byte[] RsaBlob(RSAParameters parameters)
    {
        if (parameters.Exponent is null || parameters.Modulus is null)
            throw new PublicKeyFormatException("The RSA key has no modulus or exponent.");
        var writer = new BlobWriter();
        writer.WriteString(Encoding.ASCII.GetBytes(Rsa));
        writer.WriteMpint(parameters.Exponent);
        writer.WriteMpint(parameters.Modulus);
        return writer.ToArray();
    }

    private static PublicKeyEntry ParseLine(string line, PublicKeySource source, DateTime addedAtUtc)
    {
        var parts = line.Split((char[]?)null, 3, StringSplitOptions.RemoveEmptyEntries);
        var type = parts[0];
        if (!IsKeyTypeName(type))
        {
            if (line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Skip(1).Any(IsKeyTypeName))
                throw new PublicKeyFormatException("Key options such as from= or restrict are not supported. Remove them from the line.");
            throw new PublicKeyFormatException("This is not a public key line (type base64 [comment]).");
        }
        CheckTypeIsSupported(type);
        if (parts.Length < 2)
            throw new PublicKeyFormatException("The line has no key data.");

        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(parts[1]);
        }
        catch (FormatException)
        {
            throw new PublicKeyFormatException("The key data is not valid base64.");
        }

        var entry = FromBlob(blob, parts.Length > 2 ? parts[2].Trim() : null, source, addedAtUtc, checkRsaSize: true);
        if (entry.KeyType != type)
            throw new PublicKeyFormatException($"The line says {type}, but the key data is {entry.KeyType}.");
        return entry;
    }

    private static PublicKeyEntry FromPem(string pem, PublicKeySource source, DateTime addedAtUtc)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return FromBlob(RsaBlob(rsa.ExportParameters(false)), null, source, addedAtUtc, checkRsaSize: true);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            // Not an RSA key; try ECDSA.
        }

        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);
            return FromBlob(EcdsaBlob(ecdsa.ExportParameters(false)), null, source, addedAtUtc, checkRsaSize: true);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            throw new PublicKeyFormatException("The PEM text is not an RSA or ECDSA public key.");
        }
    }

    private static byte[] EcdsaBlob(ECParameters parameters)
    {
        var (type, curve) = parameters.Curve.Oid?.Value switch
        {
            "1.2.840.10045.3.1.7" => (EcdsaNistP256, "nistp256"),
            "1.3.132.0.34" => (EcdsaNistP384, "nistp384"),
            "1.3.132.0.35" => (EcdsaNistP521, "nistp521"),
            _ => throw new PublicKeyFormatException("Only the ECDSA curves nistp256, nistp384 and nistp521 are supported."),
        };
        var writer = new BlobWriter();
        writer.WriteString(Encoding.ASCII.GetBytes(type));
        writer.WriteString(Encoding.ASCII.GetBytes(curve));
        writer.WriteString([0x04, .. parameters.Q.X!, .. parameters.Q.Y!]);
        return writer.ToArray();
    }

    private static PublicKeyEntry FromBlob(byte[] blob, string? comment, PublicKeySource source, DateTime addedAtUtc, bool checkRsaSize)
    {
        ArgumentNullException.ThrowIfNull(blob);
        var reader = new BlobReader(blob);
        var type = Encoding.ASCII.GetString(reader.ReadString());
        CheckTypeIsSupported(type);

        switch (type)
        {
            case Ed25519:
                if (reader.ReadString().Length != 32)
                    throw new PublicKeyFormatException("The ssh-ed25519 key does not have 32 bytes.");
                break;
            case Rsa:
                var exponent = reader.ReadMpint();
                var modulus = reader.ReadMpint();
                if (exponent.Length == 0 || (exponent[^1] & 1) == 0)
                    throw new PublicKeyFormatException("The RSA key has an invalid exponent.");
                var bits = BitLength(modulus);
                if (checkRsaSize && bits < MinimumRsaBits)
                    throw new PublicKeyFormatException($"The RSA key has {bits} bits; at least {MinimumRsaBits} are needed.");
                if (bits < 512)
                    throw new PublicKeyFormatException("The RSA key has an invalid modulus.");
                break;
            default: // ECDSA
                var curve = Encoding.ASCII.GetString(reader.ReadString());
                if (type != "ecdsa-sha2-" + curve)
                    throw new PublicKeyFormatException($"The {type} key names the curve {curve}.");
                var pointLength = curve switch { "nistp256" => 65, "nistp384" => 97, _ => 133 };
                var point = reader.ReadString();
                if (point.Length != pointLength || point[0] != 0x04)
                    throw new PublicKeyFormatException($"The {type} key has an invalid point.");
                break;
        }
        if (!reader.AtEnd)
            throw new PublicKeyFormatException("The key data has extra bytes after the key.");

        return new PublicKeyEntry
        {
            KeyType = type,
            KeyBase64 = Convert.ToBase64String(blob),
            Fingerprint = Fingerprint(blob),
            Comment = string.IsNullOrWhiteSpace(comment) ? null : comment,
            AddedAt = addedAtUtc,
            Source = source,
        };
    }

    private static bool IsKeyTypeName(string token) =>
        SupportedKeyTypes.Contains(token) || token == "ssh-dss" || token.StartsWith("sk-", StringComparison.Ordinal)
        || token.EndsWith("-cert-v01@openssh.com", StringComparison.Ordinal) || token.StartsWith("ecdsa-sha2-", StringComparison.Ordinal);

    private static void CheckTypeIsSupported(string type)
    {
        if (SupportedKeyTypes.Contains(type))
            return;
        if (type.EndsWith("-cert-v01@openssh.com", StringComparison.Ordinal))
            throw new PublicKeyFormatException("SSH certificates are not supported. Add the public key itself.");
        if (type == "ssh-dss")
            throw new PublicKeyFormatException("DSA keys are not supported. Use an ed25519, ECDSA or RSA key.");
        if (type.StartsWith("sk-", StringComparison.Ordinal))
            throw new PublicKeyFormatException("Security keys (sk-...) are not supported. Use an ed25519, ECDSA or RSA key.");
        throw new PublicKeyFormatException("The key type is not supported. Use an ed25519, ECDSA or RSA key.");
    }

    private static int BitLength(byte[] unsignedBigEndian)
    {
        var i = 0;
        while (i < unsignedBigEndian.Length && unsignedBigEndian[i] == 0)
            i++;
        if (i == unsignedBigEndian.Length)
            return 0;
        var bits = (unsignedBigEndian.Length - i - 1) * 8;
        for (var b = unsignedBigEndian[i]; b != 0; b >>= 1)
            bits++;
        return bits;
    }

    private sealed class BlobReader(byte[] data)
    {
        private int _position;

        public bool AtEnd => _position == data.Length;

        public byte[] ReadString()
        {
            if (data.Length - _position < 4)
                throw new PublicKeyFormatException("The key data is truncated.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(_position));
            _position += 4;
            if (length > (uint)(data.Length - _position))
                throw new PublicKeyFormatException("The key data is truncated.");
            var value = data.AsSpan(_position, (int)length).ToArray();
            _position += (int)length;
            return value;
        }

        /// <summary>An mpint (RFC 4251 section 5) that must be positive; returned without the sign byte.</summary>
        public byte[] ReadMpint()
        {
            var value = ReadString();
            if (value.Length > 0 && (value[0] & 0x80) != 0)
                throw new PublicKeyFormatException("The key data has a negative number.");
            return value.AsSpan().TrimStart((byte)0).ToArray();
        }
    }

    private sealed class BlobWriter
    {
        private readonly MemoryStream _stream = new();

        public void WriteString(ReadOnlySpan<byte> value)
        {
            Span<byte> length = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(length, (uint)value.Length);
            _stream.Write(length);
            _stream.Write(value);
        }

        public void WriteMpint(byte[] unsignedBigEndian)
        {
            var value = unsignedBigEndian.AsSpan().TrimStart((byte)0);
            if (value.Length > 0 && (value[0] & 0x80) != 0)
                WriteString([0, .. value]);
            else
                WriteString(value);
        }

        public byte[] ToArray() => _stream.ToArray();
    }
}
