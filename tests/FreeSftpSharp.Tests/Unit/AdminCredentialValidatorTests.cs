using System.Net;
using FxSshSftpServer.Security;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>The admin login checks the stored administrators (#60): name, password, status and allowed networks.</summary>
public sealed class AdminCredentialValidatorTests
{
    private static readonly string Hash = PasswordHasher.Hash("s3cret!", PasswordHasher.MinimumIterations);
    private static readonly IPAddress Client = IPAddress.Parse("192.0.2.10");

    private readonly InMemoryAdminStore _store = new();
    private readonly AdminCredentialValidator _validator;

    public AdminCredentialValidatorTests()
    {
        _validator = new AdminCredentialValidator(_store);
        Add(new Admin { Username = "admin", PasswordHash = Hash, Permissions = AdminPermissions.SuperAdmin });
    }

    private void Add(Admin admin) => Assert.True(_store.AddAdminAsync(admin, CancellationToken.None).Result);

    private Task<Admin> Validate(string? userName, string? password, IPAddress? client = null) =>
        _validator.ValidateAsync(userName!, password!, client ?? Client, TestContext.Current.CancellationToken);

    [Fact]
    public async Task Correct_user_name_and_password_are_accepted()
    {
        var admin = await Validate("admin", "s3cret!");

        Assert.Equal("admin", admin.Username);
    }

    [Fact]
    public async Task User_name_match_ignores_case_but_password_does_not()
    {
        Assert.NotNull(await Validate("ADMIN", "s3cret!"));
        Assert.Null(await Validate("admin", "S3CRET!"));
    }

    [Theory]
    [InlineData("admin", "wrong")]
    [InlineData("root", "s3cret!")]
    [InlineData("", "s3cret!")]
    [InlineData(null, null)]
    public async Task Wrong_credentials_are_rejected(string? userName, string? password)
    {
        Assert.Null(await Validate(userName, password));
    }

    [Fact]
    public async Task A_disabled_administrator_cannot_log_in()
    {
        Add(new Admin { Username = "off", PasswordHash = Hash, Status = AdminStatus.Disabled, Permissions = AdminPermissions.ManageUsers });

        Assert.Null(await Validate("off", "s3cret!"));
    }

    [Fact]
    public async Task An_administrator_with_allowed_networks_logs_in_only_from_them()
    {
        Add(new Admin { Username = "lan", PasswordHash = Hash, AllowedIps = ["10.0.0.0/8"], Permissions = AdminPermissions.ManageUsers });

        Assert.NotNull(await Validate("lan", "s3cret!", IPAddress.Parse("10.1.2.3")));
        Assert.NotNull(await Validate("lan", "s3cret!", IPAddress.Parse("::ffff:10.1.2.3")));
        Assert.Null(await Validate("lan", "s3cret!", IPAddress.Parse("192.0.2.10")));
    }

    [Fact]
    public async Task Nothing_is_accepted_when_no_administrator_is_stored()
    {
        var validator = new AdminCredentialValidator(new InMemoryAdminStore());

        Assert.Null(await validator.ValidateAsync("admin", "s3cret!", Client, TestContext.Current.CancellationToken));
    }
}
