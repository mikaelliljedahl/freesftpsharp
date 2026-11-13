using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SshServer.Interfaces.Net;

/// <summary>
/// Parses and matches IP network entries in CIDR notation ("10.0.0.0/8", "2001:db8::/32") or single addresses
/// ("10.1.2.3", "::1"). The server uses it for the global blacklist and whitelist and the per-user whitelist; the
/// admin UI uses <see cref="IsValid"/> / <see cref="FindInvalid"/> to validate input.
/// <list type="bullet">
/// <item>A single address is a network with the full prefix (/32 or /128).</item>
/// <item>Host bits after the prefix are ignored: "192.168.1.5/24" is "192.168.1.0/24".</item>
/// <item>IPv4-mapped IPv6 addresses ("::ffff:10.1.2.3") are IPv4: a dual-stack socket gives IPv4 clients this form.</item>
/// <item>Host names, scope ids ("fe80::1%eth0") and anything else are invalid.</item>
/// </list>
/// </summary>
public static class CidrNotation
{
    /// <summary>Parses one entry. Returns false for null, empty or invalid text.</summary>
    public static bool TryParse([NotNullWhen(true)] string? text, out IPNetwork network)
    {
        network = default;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        var value = text.Trim();
        var slash = value.IndexOf('/');
        var addressText = slash < 0 ? value : value[..slash];
        if (addressText.Contains('%') || !IPAddress.TryParse(addressText, out var address))
            return false;
        // IPAddress.TryParse accepts forms such as "10.0.0" or "1"; only the full dotted form is valid here.
        if (address.AddressFamily == AddressFamily.InterNetwork && addressText.Count(c => c == '.') != 3)
            return false;

        var maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var prefix = maxPrefix;
        if (slash >= 0)
        {
            var prefixText = value[(slash + 1)..];
            if (prefixText.Length is 0 or > 3 || !prefixText.All(char.IsAsciiDigit)
                || !int.TryParse(prefixText, NumberStyles.None, CultureInfo.InvariantCulture, out prefix)
                || prefix > maxPrefix)
                return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            if (prefix < 96)
                return false;
            address = address.MapToIPv4();
            prefix -= 96;
        }

        network = new IPNetwork(MaskHostBits(address, prefix), prefix);
        return true;
    }

    /// <summary>True when <paramref name="text"/> is a valid entry.</summary>
    public static bool IsValid(string? text) => TryParse(text, out _);

    /// <summary>The invalid entries of a list, in order. Empty when all are valid or the list is null.</summary>
    public static IReadOnlyList<string> FindInvalid(IEnumerable<string?>? entries) =>
        entries?.Where(e => !IsValid(e)).Select(e => e ?? "").ToList() ?? new List<string>();

    /// <summary>Parses the valid entries of a list. <paramref name="onInvalid"/> is called for each invalid entry.</summary>
    public static IReadOnlyList<IPNetwork> ParseValid(IEnumerable<string?>? entries, Action<string>? onInvalid = null)
    {
        var networks = new List<IPNetwork>();
        if (entries == null)
            return networks;

        foreach (var entry in entries)
        {
            if (TryParse(entry, out var network))
                networks.Add(network);
            else
                onInvalid?.Invoke(entry ?? "");
        }
        return networks;
    }

    /// <summary>True when one of the networks contains the address (after <see cref="Normalize"/>).</summary>
    public static bool Contains(IEnumerable<IPNetwork> networks, IPAddress address)
    {
        var normalized = Normalize(address);
        foreach (var network in networks)
        {
            if (network.BaseAddress.AddressFamily == normalized.AddressFamily && network.Contains(normalized))
                return true;
        }
        return false;
    }

    /// <summary>An IPv4-mapped IPv6 address becomes the IPv4 address; other addresses stay the same.</summary>
    public static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static IPAddress MaskHostBits(IPAddress address, int prefix)
    {
        var bytes = address.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++)
        {
            var bitsInByte = Math.Clamp(prefix - i * 8, 0, 8);
            bytes[i] &= (byte)(0xFF << (8 - bitsInByte));
        }
        return new IPAddress(bytes);
    }
}
