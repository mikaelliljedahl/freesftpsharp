namespace SshServer.Interfaces.TwoFactor;

/// <summary>Who has a second factor: an SFTP <see cref="User"/> or an <see cref="Admins.Admin"/>.</summary>
public enum TwoFactorSubjectKind
{
    User,
    Admin,
}

/// <summary>The owner of a TOTP enrolment: the kind and the stored id (<see cref="User.Id"/> or <see cref="Admins.Admin.Id"/>).</summary>
public readonly record struct TwoFactorSubject(TwoFactorSubjectKind Kind, int Id)
{
    public static TwoFactorSubject ForUser(User user) => new(TwoFactorSubjectKind.User, user.Id);

    public static TwoFactorSubject ForAdmin(Admins.Admin admin) => new(TwoFactorSubjectKind.Admin, admin.Id);

    public override string ToString() => $"{Kind} {Id}";
}
