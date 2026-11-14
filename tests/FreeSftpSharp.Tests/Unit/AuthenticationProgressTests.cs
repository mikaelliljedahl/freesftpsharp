using FxSsh.SshServerModule.Security;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>
/// The allowed login methods and the order of a multi-step login (issue #58), with the TOTP code step (issue #63):
/// <see cref="AuthenticationProgress"/> (the state of one SSH session) and <see cref="AuthMethodRules.Validate"/>.
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

        Assert.Null(progress.Check(user, AuthMethods.Password, totp: false));
        Assert.Null(progress.Check(user, AuthMethods.PublicKey, totp: false));
        Assert.True(progress.IsLastStep(user, totp: false));
        Assert.Null(progress.MethodsThatCanContinue(user, totp: false));
        Assert.Equal("password", progress.Describe(AuthMethods.Password));
    }

    [Fact]
    public void A_method_that_is_not_allowed_is_refused()
    {
        var progress = new AuthenticationProgress();
        var keyOnly = UserWith(AuthMethods.PublicKey);

        Assert.Equal("the method is not allowed for the user", progress.Check(keyOnly, AuthMethods.Password, totp: false));
        Assert.Null(progress.Check(keyOnly, AuthMethods.PublicKey, totp: false));
        Assert.NotNull(progress.Check(UserWith(AuthMethods.Password), AuthMethods.PublicKey, totp: false));
        Assert.NotNull(progress.Check(UserWith(AuthMethods.None), AuthMethods.Password, totp: false));
    }

    [Fact]
    public void None_and_unknown_methods_are_refused()
    {
        Assert.Equal("the method is not supported", new AuthenticationProgress().Check(UserWith(), AuthMethods.None, totp: false));
    }

    [Fact]
    public void A_multi_step_login_needs_the_steps_in_their_order()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);

        // The password first is refused, also when it is right.
        Assert.Equal("the method is not the next step of the multi-step login", progress.Check(user, AuthMethods.Password, totp: false));
        Assert.Null(progress.Check(user, AuthMethods.PublicKey, totp: false));
        Assert.False(progress.IsLastStep(user, totp: false));

        progress.CompleteStep(user, AuthMethods.PublicKey, totp: false);

        Assert.Equal(new[] { "password" }, progress.MethodsThatCanContinue(user, totp: false));
        Assert.NotNull(progress.Check(user, AuthMethods.PublicKey, totp: false)); // a second key does not help
        Assert.Null(progress.Check(user, AuthMethods.Password, totp: false));
        Assert.True(progress.IsLastStep(user, totp: false));
        Assert.Equal("publickey,password", progress.Describe(AuthMethods.Password));
    }

    [Fact]
    public void The_reverse_order_works_when_the_user_is_configured_so()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith(AuthMethods.All, AuthMethods.Password, AuthMethods.PublicKey);

        Assert.NotNull(progress.Check(user, AuthMethods.PublicKey, totp: false));
        Assert.Null(progress.Check(user, AuthMethods.Password, totp: false));
        progress.CompleteStep(user, AuthMethods.Password, totp: false);

        Assert.Equal(new[] { "publickey" }, progress.MethodsThatCanContinue(user, totp: false));
        Assert.Null(progress.Check(user, AuthMethods.PublicKey, totp: false));
    }

    [Fact]
    public void A_step_of_another_user_does_not_count()
    {
        var progress = new AuthenticationProgress();
        var alice = UserWith(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);
        var bob = new User { Username = "bob", RequireAllOf = [AuthMethods.PublicKey, AuthMethods.Password] };

        progress.CompleteStep(alice, AuthMethods.PublicKey, totp: false);

        Assert.NotNull(progress.Check(bob, AuthMethods.Password, totp: false));
        Assert.Null(progress.MethodsThatCanContinue(bob, totp: false));
        // ... and the switch forgot alice's step too.
        Assert.NotNull(progress.Check(alice, AuthMethods.Password, totp: false));
    }

    [Fact]
    public void A_change_of_the_steps_by_the_admin_starts_again()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);
        progress.CompleteStep(user, AuthMethods.PublicKey, totp: false);

        user.RequireAllOf = [AuthMethods.Password, AuthMethods.PublicKey];

        Assert.Null(progress.Check(user, AuthMethods.Password, totp: false));
        Assert.Empty(progress.Completed);
        Assert.False(progress.IsLastStep(user, totp: false));
    }

    [Fact]
    public void Reset_forgets_the_done_steps()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);
        progress.CompleteStep(user, AuthMethods.PublicKey, totp: false);

        progress.Reset();

        Assert.NotNull(progress.Check(user, AuthMethods.Password, totp: false));
    }

    [Fact]
    public void A_method_that_is_allowed_no_more_is_refused_also_as_the_next_step()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);
        progress.CompleteStep(user, AuthMethods.PublicKey, totp: false);

        user.AllowedAuthMethods = AuthMethods.PublicKey;

        Assert.Equal("the method is not allowed for the user", progress.Check(user, AuthMethods.Password, totp: false));
    }

    [Fact]
    public void A_totp_user_without_a_multi_step_login_needs_one_method_and_then_the_code()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith();

        Assert.Null(progress.Check(user, AuthMethods.Password, totp: true));
        Assert.Null(progress.Check(user, AuthMethods.PublicKey, totp: true));
        Assert.False(progress.KeyboardInteractiveAsksForCode(user, totp: true)); // keyboard-interactive first is the password
        Assert.False(progress.IsLastStep(user, totp: true));

        progress.CompleteStep(user, AuthMethods.Password, totp: true);

        Assert.Equal(new[] { "keyboard-interactive" }, progress.MethodsThatCanContinue(user, totp: true));
        Assert.NotNull(progress.Check(user, AuthMethods.Password, totp: true));
        Assert.NotNull(progress.Check(user, AuthMethods.PublicKey, totp: true));
        Assert.Null(progress.Check(user, AuthMethods.KeyboardInteractive, totp: true));
        Assert.True(progress.KeyboardInteractiveAsksForCode(user, totp: true));
        Assert.True(progress.IsLastStep(user, totp: true));
        Assert.Equal("password,keyboard-interactive", progress.Describe(AuthMethods.KeyboardInteractive));
    }

    [Fact]
    public void The_code_step_needs_no_allowed_keyboard_interactive()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith(AuthMethods.Password);

        Assert.NotNull(progress.Check(user, AuthMethods.KeyboardInteractive, totp: true)); // not as the first factor
        progress.CompleteStep(user, AuthMethods.Password, totp: true);

        Assert.Null(progress.Check(user, AuthMethods.KeyboardInteractive, totp: true));
    }

    [Fact]
    public void A_totp_user_with_a_multi_step_login_gives_the_code_after_the_last_step()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);

        progress.CompleteStep(user, AuthMethods.PublicKey, totp: true);
        Assert.False(progress.IsLastStep(user, totp: true));
        progress.CompleteStep(user, AuthMethods.Password, totp: true);

        Assert.Equal(new[] { "keyboard-interactive" }, progress.MethodsThatCanContinue(user, totp: true));
        Assert.True(progress.KeyboardInteractiveAsksForCode(user, totp: true));
        Assert.True(progress.IsLastStep(user, totp: true));
    }

    [Fact]
    public void A_keyboard_interactive_step_is_the_code_with_totp_and_the_password_without()
    {
        var user = UserWith(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.KeyboardInteractive);

        var withTotp = new AuthenticationProgress();
        withTotp.CompleteStep(user, AuthMethods.PublicKey, totp: true);
        Assert.True(withTotp.KeyboardInteractiveAsksForCode(user, totp: true));
        Assert.True(withTotp.IsLastStep(user, totp: true)); // no extra code step: the configured step is it

        var withoutTotp = new AuthenticationProgress();
        withoutTotp.CompleteStep(user, AuthMethods.PublicKey, totp: false);
        Assert.Null(withoutTotp.Check(user, AuthMethods.KeyboardInteractive, totp: false));
        Assert.False(withoutTotp.KeyboardInteractiveAsksForCode(user, totp: false));
        Assert.True(withoutTotp.IsLastStep(user, totp: false));
    }

    [Fact]
    public void Without_totp_keyboard_interactive_alone_is_the_password_and_enough()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith();

        Assert.Null(progress.Check(user, AuthMethods.KeyboardInteractive, totp: false));
        Assert.False(progress.KeyboardInteractiveAsksForCode(user, totp: false));
        Assert.True(progress.IsLastStep(user, totp: false));
    }

    [Fact]
    public void A_reset_of_the_second_factor_during_the_login_starts_again()
    {
        var progress = new AuthenticationProgress();
        var user = UserWith();
        progress.CompleteStep(user, AuthMethods.Password, totp: true);

        // The admin resets the second factor: there is no code step any more, and the done step is forgotten.
        Assert.Null(progress.MethodsThatCanContinue(user, totp: false));
        Assert.Empty(progress.Completed);
        Assert.True(progress.IsLastStep(user, totp: false));
    }

    [Fact]
    public void Valid_settings_have_no_problems()
    {
        Assert.Empty(AuthMethodRules.Validate(AuthMethods.All, null));
        Assert.Empty(AuthMethodRules.Validate(AuthMethods.PublicKey, []));
        Assert.Empty(AuthMethodRules.Validate(AuthMethods.Password | AuthMethods.PublicKey, [AuthMethods.PublicKey, AuthMethods.Password]));
        Assert.Empty(AuthMethodRules.Validate(AuthMethods.All, [AuthMethods.Password, AuthMethods.PublicKey]));
        Assert.Empty(AuthMethodRules.Validate(AuthMethods.All, [AuthMethods.PublicKey, AuthMethods.KeyboardInteractive]));
    }

    [Theory]
    [InlineData(AuthMethods.None, new AuthMethods[0], "at least one")]
    [InlineData((AuthMethods)8, new AuthMethods[0], "unknown")]
    [InlineData(AuthMethods.All, new[] { AuthMethods.PublicKey }, "at least two")]
    [InlineData(AuthMethods.PublicKey, new[] { AuthMethods.PublicKey, AuthMethods.Password }, "not an allowed method")]
    [InlineData(AuthMethods.All, new[] { AuthMethods.PublicKey, AuthMethods.PublicKey }, "only once")]
    [InlineData(AuthMethods.All, new[] { AuthMethods.KeyboardInteractive, AuthMethods.PublicKey }, "cannot be the first step")]
    [InlineData(AuthMethods.PublicKey | AuthMethods.Password, new[] { AuthMethods.PublicKey, AuthMethods.KeyboardInteractive }, "not an allowed method")]
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
