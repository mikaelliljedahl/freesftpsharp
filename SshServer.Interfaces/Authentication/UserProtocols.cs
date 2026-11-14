namespace SshServer.Interfaces.Authentication;

/// <summary>
/// The protocols that a user may log in with (issue #71, <see cref="User.AllowedProtocols"/>). Flags, so that a user can
/// allow several. SFTP refuses a protocol that is not allowed like a wrong credential; WebDAV checks it after the
/// password and answers 403.
/// </summary>
[Flags]
public enum UserProtocols
{
    None = 0,
    Sftp = 1,
    WebDav = 2,

    /// <summary>The web client in the browser (#69), when it is on for the server.</summary>
    Web = 4,

    /// <summary>FTP and FTPS (issue #72). Checked after the password, like WebDAV; the client gets 530.</summary>
    Ftp = 8,

    /// <summary>Every protocol. Stored by name, so a user with "All" also gets a protocol that a later version adds.</summary>
    All = Sftp | WebDav | Web | Ftp,
}

/// <summary>The rules of <see cref="UserProtocols"/>.</summary>
public static class UserProtocolRules
{
    /// <summary>The protocols that the admin UI shows, with their names.</summary>
    public static readonly IReadOnlyList<(UserProtocols Protocol, string Name)> Known =
        [(UserProtocols.Sftp, "SFTP"), (UserProtocols.WebDav, "WebDAV"), (UserProtocols.Web, "Web client"), (UserProtocols.Ftp, "FTP")];

    /// <summary>True when <paramref name="allowed"/> contains <paramref name="protocol"/>.</summary>
    public static bool Allows(this UserProtocols allowed, UserProtocols protocol) => protocol != UserProtocols.None && (allowed & protocol) == protocol;

    /// <summary>"SFTP, WebDAV, FTP" for display; "none" for no protocol.</summary>
    public static string Describe(UserProtocols protocols)
    {
        var names = Known.Where(k => (protocols & k.Protocol) != 0).Select(k => k.Name).ToList();
        return names.Count == 0 ? "none" : string.Join(", ", names);
    }
}
