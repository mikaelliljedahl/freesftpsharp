using FxSsh.SshServerModule.Security;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>
/// The allowed login methods and the order of a multi-step login (issue #58): <see cref="AuthenticationProgress"/>
/// (the state of one SSH session) and <see cref="AuthMethodRules.Validate"/>.
/// </summary>
public sealed class AuthenticationProgressTests
{
    private static User UserWith(AuthMethods allowed = AuthMethods.All, params AuthMethods[] steps) =>
        new() { Username = "alice", AllowedAuthMethods = allowed, RequireAllOf = steps.Length == 0 ? null : steps.ToList() };

    [Fact]
    public void By_default_every_supported_method_may_be_tried_and_one_is_enough()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith();

        Assert.Null(progress.Check(user, AuthMethods.Password));
        Assert.Null(progress.Check(user, AuthMethods.PublicKey));
        Assert.True(progress.IsLastStep(user));
        Assert.Null(progress.MethodsThatCanContinue(user));
        Assert.Equal("password", progress.Describe(AuthMethods.Password));
    }

    [Fact]
    public void A_method_that_is_not_allowed_is_refused()
    {
        var progress = new AuthenticationProgress();
        var keyOnly = UserWith(AuthMethods.PublicKey);

        Assert.Equal("the method is not allowed for the user", progress.Check(keyOnly, AuthMethods.Password));
        Assert.Null(progress.Check(keyOnly, AuthMethods.PublicKey));
        Assert.NotNull(progress.Check(UserWith(AuthMethods.Password), AuthMethods.PublicKey));
        Assert.NotNull(progress.Check(UserWith(AuthMethods.None), AuthMethods.Password));
    }

    [Fact]
    public void None_and_unknown_methods_are_refused()
    {
        Assert.Equal("the method is not supported", new AuthenticationProgress().Check(UserWith(), AuthMethods.None));
    }

    [Fact]
    public void A_multi_step_login_needs_the_steps_in_their_order()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);

        // The password first is refused, also when it is right.
        Assert.Equal("the method is not the next step of the multi-step login", progress.Check(user, AuthMethods.Password));
        Assert.Null(progress.Check(user, AuthMethods.PublicKey));
        Assert.False(progress.IsLastStep(user));

        progress.CompleteStep(user, AuthMethods.PublicKey);

        Assert.Equal(new[] { "password" }, progress.MethodsThatCanContinue(user));
        Assert.NotNull(progress.Check(user, AuthMethods.PublicKey)); // a second key does not help
        Assert.Null(progress.Check(user, AuthMethods.Password));
        Assert.True(progress.IsLastStep(user));
        Assert.Equal("publickey,password", progress.Describe(AuthMethods.Password));
    }

    [Fact]
    public void The_reverse_order_works_when_the_user_is_configured_so()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith(AuthMethods.All, AuthMethods.Password, AuthMethods.PublicKey);

        Assert.NotNull(progress.Check(user, AuthMethods.PublicKey));
        Assert.Null(progress.Check(user, AuthMethods.Password));
        progress.CompleteStep(user, AuthMethods.Password);

        Assert.Equal(new[] { "publickey" }, progress.MethodsThatCanContinue(user));
        Assert.Null(progress.Check(user, AuthMethods.PublicKey));
    }

    [Fact]
    public void A_step_of_another_user_does_not_count()
    {
        var progress = new AuthenticationProgress();
        var alice = UserWith(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);
        var bob = new User { Username = "bob", RequireAllOf = [AuthMethods.PublicKey, AuthMethods.Password] };

        progress.CompleteStep(alice, AuthMethods.PublicKey);

        Assert.NotNull(progress.Check(bob, AuthMethods.Password));
        Assert.Null(progress.MethodsThatCanContinue(bob));
        // ... and the switch forgot alice's step too.
        Assert.NotNull(progress.Check(alice, AuthMethods.Password));
    }

    [Fact]
    public void A_change_of_the_steps_by_the_admin_starts_again()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);
        progress.CompleteStep(user, AuthMethods.PublicKey);

        user.RequireAllOf = [AuthMethods.Password, AuthMethods.PublicKey];

        Assert.Null(progress.Check(user, AuthMethods.Password));
        Assert.Empty(progress.Completed);
        Assert.False(progress.IsLastStep(user));
    }

    [Fact]
    public void Reset_forgets_the_done_steps()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);
        progress.CompleteStep(user, AuthMethods.PublicKey);

        progress.Reset();

        Assert.NotNull(progress.Check(user, AuthMethods.Password));
    }

    [Fact]
    public void A_method_that_is_allowed_no_more_is_refused_also_as_the_next_step()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);
        progress.CompleteStep(user, AuthMethods.PublicKey);

        user.AllowedAuthMethods = AuthMethods.PublicKey;

        Assert.Equal("the method is not allowed for the user", progress.Check(user, AuthMethods.Password));
    }

    [Fact]
    public void Valid_settings_have_no_problems()
    {
        Assert.Empty(AuthMethodRules.Validate(AuthMethods.All, null));
        Assert.Empty(AuthMethodRules.Validate(AuthMethods.PublicKey, []));
        Assert.Empty(AuthMethodRules.Validate(AuthMethods.Password | AuthMethods.PublicKey, [AuthMethods.PublicKey, AuthMethods.Password]));
        Assert.Empty(AuthMethodRules.Validate(AuthMethods.All, [AuthMethods.Password, AuthMethods.PublicKey]));
    }

    [Theory]
    [InlineData(AuthMethods.None, new AuthMethods[0], "at least one")]
    [InlineData((AuthMethods)8, new AuthMethods[0], "unknown")]
    [InlineData(AuthMethods.All, new[] { AuthMethods.PublicKey }, "at least two")]
    [InlineData(AuthMethods.PublicKey, new[] { AuthMethods.PublicKey, AuthMethods.Password }, "not an allowed method")]
    [InlineData(AuthMethods.All, new[] { AuthMethods.PublicKey, AuthMethods.PublicKey }, "only once")]
    [InlineData(AuthMethods.All, new[] { AuthMethods.PublicKey, AuthMethods.KeyboardInteractive }, "cannot be a step")]
    [InlineData(AuthMethods.All, new[] { AuthMethods.PublicKey, AuthMethods.Password | AuthMethods.PublicKey }, "cannot be a step")]
    public void Invalid_settings_are_reported(AuthMethods allowed, AuthMethods[] steps, string problem)
    {
        var problems = AuthMethodRules.Validate(allowed, steps);

        Assert.Contains(problems, p => p.Contains(problem, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("password", AuthMethods.Password)]
    [InlineData("publickey", AuthMethods.PublicKey)]
    [InlineData("keyboard-interactive", AuthMethods.KeyboardInteractive)]
    [InlineData("none", AuthMethods.None)]
    [InlineData("hostbased", AuthMethods.None)]
    [InlineData(null, AuthMethods.None)]
    public void Ssh_method_names_map_to_the_methods(string? name, AuthMethods method)
    {
        Assert.Equal(method, AuthMethodRules.FromSshName(name));
    }
}
