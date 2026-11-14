using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SshServer.Webhooks;

/// <summary>
/// The signature of a webhook request: <c>X-FreeSftpSharp-Signature: t=&lt;unix seconds&gt;,v1=&lt;hex&gt;</c>, where
/// the hex is the lower-case HMAC-SHA256 of <c>t + "." + body</c> with the secret of the webhook (UTF-8). A receiver
/// computes the same value and compares it in constant time, and refuses an old <c>t</c> (replay). See
/// docs/WEBHOOKS.md.
/// </summary>
public static class WebhookSignature
{
    public const string SignatureHeader = "X-FreeSftpSharp-Signature";
    public const string EventHeader = "X-FreeSftpSharp-Event";
    public const string DeliveryHeader = "X-FreeSftpSharp-Delivery";

    /// <summary>The header value for a body sent at <paramref name="unixSeconds"/>.</summary>
    public static string Create(string secret, long unixSeconds, string body)
        => $"t={unixSeconds.ToString(CultureInfo.InvariantCulture)},v1={ComputeV1(secret, unixSeconds, body)}";

    /// <summary>The lower-case hex HMAC-SHA256 of <c>t + "." + body</c>.</summary>
    public static string ComputeV1(string secret, long unixSeconds, string body)
    {
        var message = Encoding.UTF8.GetBytes(unixSeconds.ToString(CultureInfo.InvariantCulture) + "." + body);
        return Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), message));
    }

    /// <summary>
    /// Checks a header value as a receiver does: a <c>v1</c> that matches, and a <c>t</c> within
    /// <paramref name="tolerance"/> of <paramref name="now"/>.
    /// </summary>
    public static bool Verify(string secret, string? header, string body, DateTimeOffset now, TimeSpan tolerance)
    {
        if (string.IsNullOrEmpty(header))
            return false;
        long? t = null;
        var signatures = new List<string>();
        foreach (var part in header.Split(','))
        {
            var pair = part.Trim().Split('=', 2);
            if (pair.Length != 2)
                continue;
            if (pair[0] == "t" && long.TryParse(pair[1], NumberStyles.None, CultureInfo.InvariantCulture, out var value))
                t = value;
            else if (pair[0] == "v1")
                signatures.Add(pair[1]);
        }
        if (t is not { } timestamp || Math.Abs(now.ToUnixTimeSeconds() - timestamp) > tolerance.TotalSeconds)
            return false;

        var expected = Encoding.ASCII.GetBytes(ComputeV1(secret, timestamp, body));
        return signatures.Any(s => CryptographicOperations.FixedTimeEquals(expected, Encoding.ASCII.GetBytes(s)));
    }
}
