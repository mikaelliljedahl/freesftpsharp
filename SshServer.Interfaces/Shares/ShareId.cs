using System.Buffers.Text;
using System.Security.Cryptography;

namespace SshServer.Interfaces.Shares;

/// <summary>The id of a share link: 160 random bits from the system CSPRNG, base64url without padding (27 characters).</summary>
public static class ShareId
{
    public const int Bytes = 20;

    /// <summary>The length of an id: 20 bytes in base64url without padding.</summary>
    public const int Length = 27;

    public static string New() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(Bytes));

    /// <summary>True for a text that can be an id; anything else is "not found" without a database read.</summary>
    public static bool IsWellFormed(string? id)
    {
        if (id is not { Length: Length })
            return false;
        foreach (var c in id)
        {
            if (!(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_'))
                return false;
        }
        return true;
    }
}
