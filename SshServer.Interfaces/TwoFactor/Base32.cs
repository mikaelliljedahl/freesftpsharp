using System.Text;

namespace SshServer.Interfaces.TwoFactor;

/// <summary>
/// Base32 of RFC 4648 section 6 (A-Z, 2-7), the encoding of TOTP secrets in <c>otpauth://</c> URIs and in the manual
/// entry of the authenticator apps. Encoded without padding; decoding ignores case, spaces, dashes and padding.
/// </summary>
public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        var builder = new StringBuilder((data.Length * 8 + 4) / 5);
        var buffer = 0;
        var bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                builder.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0)
            builder.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return builder.ToString();
    }

    /// <summary>The bytes of <paramref name="text"/>; null when it has a character outside the alphabet.</summary>
    public static byte[]? Decode(string? text)
    {
        if (text == null)
            return null;
        var output = new List<byte>(text.Length * 5 / 8);
        var buffer = 0;
        var bits = 0;
        foreach (var c in text)
        {
            if (c is ' ' or '-' or '=')
                continue;
            var value = Alphabet.IndexOf(char.ToUpperInvariant(c));
            if (value < 0)
                return null;
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)((buffer >> (bits - 8)) & 0xff));
                bits -= 8;
            }
        }
        return output.ToArray();
    }
}
