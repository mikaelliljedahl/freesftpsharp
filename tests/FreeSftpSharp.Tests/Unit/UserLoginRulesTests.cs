using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Users;

namespace FreeSftpSharp.Tests.Unit;

/// <summary><see cref="UserLoginRules"/> (issue #61): status, expiry, password age and session limit.</summary>
public sealed class UserLoginRulesTests
{
    private static readonly DateTime Now = new(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);

    private static User User(Action<User>? configure = null)
    {
        var user = new User { Username = "u", HashedPassword = "hash", PasswordChangedAt = Now.AddDays(-10) };
        configure?.Invoke(user);
        return user;
    }

    [Fact]
    public void An_enabled_user_that_does_not_expire_may_log_in()
    {
        Assert.Null(UserLoginRules.Refusal(User(), AuthMethods.Password, Now, 0));
        Assert.Null(UserLoginRules.Refusal(User(), AuthMethods.PublicKey, Now, 30));
    }

    [Theory]
    [InlineData(AuthMethods.Password)]
    [InlineData(AuthMethods.PublicKey)]
    public void A_disabled_user_is_refused_for_every_method(AuthMethods method)
    {
        Assert.Equal("the user is disabled", UserLoginRules.Refusal(User(u => u.Status = UserStatus.Disabled), method, Now, 0));
    }

    [Fact]
    public void A_user_is_refused_from_its_expiry_on()
    {
        Assert.Null(UserLoginRules.Refusal(User(u => u.ExpiresAt = Now.AddSeconds(1)), AuthMethods.PublicKey, Now, 0));
        Assert.Equal("the user expired at 2026-11-14 12:00 UTC",
            UserLoginRules.Refusal(User(u => u.ExpiresAt = Now), AuthMethods.PublicKey, Now, 0));
        // A time from the database has no kind; it is UTC.
        Assert.NotNull(UserLoginRules.Refusal(User(u => u.ExpiresAt = DateTime.SpecifyKind(Now.AddHours(-1), DateTimeKind.Unspecified)), AuthMethods.PublicKey, Now, 0));
    }

    [Fact]
    public void An_old_password_is_refused_only_for_a_password_login()
    {
        var old = User(u => u.PasswordChangedAt = Now.AddDays(-30));

        Assert.Equal("the password is older than 30 days", UserLoginRules.Refusal(old, AuthMethods.Password, Now, 30));
        Assert.Null(UserLoginRules.Refusal(old, AuthMethods.PublicKey, Now, 30));
        Assert.Null(UserLoginRules.Refusal(old, AuthMethods.Password, Now, 31));
        Assert.Null(UserLoginRules.Refusal(old, AuthMethods.Password, Now, 0)); // 0: no maximum age
    }

    [Fact]
    public void A_password_with_an_unknown_time_does_not_expire()
    {
        Assert.False(UserLoginRules.IsPasswordExpired(User(u => u.PasswordChangedAt = null), Now, 1));
        Assert.False(UserLoginRules.IsPasswordExpired(User(u => u.HashedPassword = null), Now, 1));
    }

    [Theory]
    [InlineData(0, 100, true)]
    [InlineData(2, 0, true)]
    [InlineData(2, 1, true)]
    [InlineData(2, 2, false)]
    [InlineData(1, 5, false)]
    public void The_session_limit_counts_the_other_sessions(int maxSessions, int open, bool allowed)
    {
        var refusal = UserLoginRules.SessionLimitRefusal(User(u => u.MaxSessions = maxSessions), open);

        Assert.Equal(allowed, refusal is null);
    }
}
