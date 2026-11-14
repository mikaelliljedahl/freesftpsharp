using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Authentication;

namespace SshServer.Api;

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
