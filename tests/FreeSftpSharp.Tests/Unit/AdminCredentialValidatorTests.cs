using FxSshSftpServer.Security;
using Microsoft.Extensions.Options;

namespace FreeSftpSharp.Tests.Unit;

public sealed class AdminCredentialValidatorTests
{
    private static AdminCredentialValidator Create(string? userName, string? passwordHash) =>
        new(Options.Create(new AdminAuthOptions { UserName = userName, PasswordHash = passwordHash }));

    private static readonly string Hash = AdminPasswordHasher.Hash("s3cret!", AdminPasswordHasher.MinimumIterations);

    [Fact]
    public void Correct_user_name_and_password_are_accepted()
    {
        Assert.True(Create("admin", Hash).Validate("admin", "s3cret!"));
    }

    [Fact]
    public void User_name_match_ignores_case_but_password_does_not()
    {
        var validator = Create("admin", Hash);

        Assert.True(validator.Validate("ADMIN", "s3cret!"));
        Assert.False(validator.Validate("admin", "S3CRET!"));
    }

    [Theory]
    [InlineData("admin", "wrong")]
    [InlineData("root", "s3cret!")]
    [InlineData("", "s3cret!")]
    [InlineData(null, null)]
    public void Wrong_credentials_are_rejected(string? userName, string? password)
    {
        Assert.False(Create("admin", Hash).Validate(userName, password));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("admin", null)]
    [InlineData(null, "use-hash")]
    [InlineData("admin", "s3cret!")] // plaintext instead of a hash
    public void Nothing_is_accepted_when_no_valid_credential_is_configured(string? userName, string? passwordHash)
    {
        var validator = Create(userName, passwordHash == "use-hash" ? Hash : passwordHash);

        Assert.False(validator.IsConfigured);
        Assert.False(validator.Validate("admin", "s3cret!"));
        Assert.False(validator.Validate(null, null));
    }
}
