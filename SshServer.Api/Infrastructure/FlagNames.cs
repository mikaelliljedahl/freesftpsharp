using System.Numerics;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Authentication;

namespace SshServer.Api;

/// <summary>
/// Flag enums in the API as arrays of names (<c>["ManageUsers","ViewAudit"]</c>), not as numbers or comma lists. The
/// output has the single flags; the input also takes a combined name such as <c>All</c>. Names are compared without case.
/// </summary>
internal static class FlagNames
{
    public static IReadOnlyList<string> Of<T>(T value) where T : struct, Enum
    {
        var bits = Convert.ToInt64(value);
        return Enum.GetValues<T>()
            .Where(f => BitOperations.PopCount((ulong)Convert.ToInt64(f)) == 1 && (bits & Convert.ToInt64(f)) == Convert.ToInt64(f))
            .Select(f => f.ToString())
            .ToList();
    }

    /// <summary>The flags of the names; the unknown names are in <paramref name="unknown"/>.</summary>
    public static T Parse<T>(IEnumerable<string>? names, List<string> unknown) where T : struct, Enum
    {
        long bits = 0;
        foreach (var name in names ?? [])
        {
            if (!string.IsNullOrWhiteSpace(name) && !name.Trim().All(char.IsDigit)
                && Enum.TryParse<T>(name.Trim(), ignoreCase: true, out var flag) && Enum.IsDefined(flag))
                bits |= Convert.ToInt64(flag);
            else
                unknown.Add(name ?? "");
        }
        return (T)Enum.ToObject(typeof(T), bits);
    }
}

/// <summary>The admin permissions in the API.</summary>
internal static class PermissionNames
{
    public static IReadOnlyList<string> Of(AdminPermissions permissions) => FlagNames.Of(permissions);
}

/// <summary>The login methods in the API, with their SSH names (<c>password</c>, <c>publickey</c>, <c>keyboard-interactive</c>).</summary>
internal static class AuthMethodNames
{
    public static IReadOnlyList<string> Of(AuthMethods methods) =>
        new[] { AuthMethods.Password, AuthMethods.PublicKey, AuthMethods.KeyboardInteractive }
            .Where(m => methods.HasFlag(m)).Select(AuthMethodRules.ToSshName).ToList();

    public static AuthMethods Parse(IEnumerable<string> names, List<string> unknown)
    {
        var methods = AuthMethods.None;
        foreach (var name in names)
        {
            var method = AuthMethodRules.FromSshName(name?.Trim().ToLowerInvariant());
            if (method == AuthMethods.None)
                unknown.Add(name ?? "");
            methods |= method;
        }
        return methods;
    }
}
