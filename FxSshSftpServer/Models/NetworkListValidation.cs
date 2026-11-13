using SshServer.Interfaces.Net;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net;

namespace FxSshSftpServer.Models
{
    /// <summary>Lists in the forms are text with one entry per line (commas also separate entries).</summary>
    public static class EntryList
    {
        public static List<string> Parse(string text) =>
            (text ?? "")
                .Split(new[] { '\r', '\n', ',' }, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

        public static string Format(IEnumerable<string> entries) =>
            string.Join("\n", (entries ?? Enumerable.Empty<string>()).Where(e => !string.IsNullOrWhiteSpace(e)));
    }

    /// <summary>Every entry must be a network in CIDR notation or a single address (<see cref="CidrNotation"/>).</summary>
    [AttributeUsage(AttributeTargets.Property)]
    public sealed class CidrListAttribute : ValidationAttribute
    {
        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            var invalid = CidrNotation.FindInvalid(EntryList.Parse(value as string));
            if (invalid.Count == 0)
                return ValidationResult.Success;

            return new ValidationResult(
                $"Not a valid network: {string.Join(", ", invalid)}. Use CIDR notation (10.0.0.0/8, 2001:db8::/32) or a single address (10.1.2.3).",
                validationContext.MemberName is { } member ? new[] { member } : null);
        }
    }

    /// <summary>
    /// Every entry must be an IP address the server can listen on ("127.0.0.1", "::1", "::" or "*" for all addresses).
    /// Host names and scope ids are not accepted, as in the server.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property)]
    public sealed class IpAddressListAttribute : ValidationAttribute
    {
        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            var invalid = EntryList.Parse(value as string).Where(e => !IsListenAddress(e)).ToList();
            if (invalid.Count == 0)
                return ValidationResult.Success;

            return new ValidationResult(
                $"Not a valid IP address: {string.Join(", ", invalid)}. Use addresses such as 127.0.0.1, ::1 or 192.168.1.10.",
                validationContext.MemberName is { } member ? new[] { member } : null);
        }

        internal static bool IsListenAddress(string entry)
        {
            if (entry == "*")
                return true;
            if (entry.Contains('%') || entry.Contains('/') || !IPAddress.TryParse(entry, out var address))
                return false;
            // IPAddress.TryParse accepts short forms such as "10.1"; only the full dotted form is clear.
            return address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || entry.Count(c => c == '.') == 3;
        }
    }
}
