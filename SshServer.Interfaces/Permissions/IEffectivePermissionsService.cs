namespace SshServer.Interfaces.Permissions;

/// <summary>
/// The one place that decides which permissions and path filters apply to a user. Every protocol gets them through
/// the storage decorator chain, never by reading <see cref="User.Permissions"/> itself. When groups (#61) come, they
/// are merged here ("user wins, then the primary group, then other groups").
/// </summary>
public interface IEffectivePermissionsService
{
    EffectivePermissions Resolve(User user);
}
