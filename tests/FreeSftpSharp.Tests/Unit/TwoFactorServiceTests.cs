using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces.TwoFactor;
using SshServer.TwoFactor;
using static FreeSftpSharp.Tests.Infrastructure.TwoFactorTestKit;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>
/// The TOTP second factor service (issue #63) with a fake clock: enrolment with a confirmation code, the code window,
/// replay protection, recovery codes, the per-subject limit, the reset, and the encrypted secret.
/// </summary>
public sealed class TwoFactorServiceTests
{
    private static readonly TwoFactorSubject Alice = new(TwoFactorSubjectKind.User, 7);
    private static readonly TwoFactorSubject Admin = new(TwoFactorSubjectKind.Admin, 7);

    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 11, 14, 12, 0, 10, TimeSpan.Zero));
    private readonly InMemoryTwoFactorStore _store = new();
    private readonly TwoFactorService _service;

    public TwoFactorServiceTests()
    {
        _service = CreateService(_time, _store);
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private DateTimeOffset Now => _time.GetUtcNow();

    [Fact]
    public async Task Without_a_setup_nothing_is_enabled()
    {
        Assert.False(await _service.IsEnabledAsync(Alice, Ct));
        Assert.Equal(TwoFactorState.Off, (await _service.GetStatusAsync(Alice, Ct)).State);
        Assert.Equal(TwoFactorCheck.NotEnabled, await _service.VerifyAsync(Alice, "123456", Ct));
    }

    [Fact]
    public async Task A_setup_is_off_until_it_is_confirmed_with_a_valid_code()
    {
        var setup = await _service.BeginSetupAsync(Alice, "alice", Ct);

        Assert.Equal(32, setup.SecretBase32.Length); // 160 bits
        Assert.StartsWith("otpauth://totp/FreeSftpSharp:alice?secret=" + setup.SecretBase32, setup.OtpAuthUri);
        Assert.Contains("&issuer=FreeSftpSharp&algorithm=SHA1&digits=6&period=30", setup.OtpAuthUri);
        Assert.StartsWith("<svg", setup.QrCodeSvg);
        Assert.Equal(TwoFactorState.Pending, (await _service.GetStatusAsync(Alice, Ct)).State);
        Assert.False(await _service.IsEnabledAsync(Alice, Ct));
        Assert.Equal(TwoFactorCheck.NotEnabled, await _service.VerifyAsync(Alice, Code(setup.SecretBase32, Now), Ct));

        Assert.Null(await _service.ConfirmSetupAsync(Alice, "000000", Ct));
        Assert.False(await _service.IsEnabledAsync(Alice, Ct));

        var codes = await _service.ConfirmSetupAsync(Alice, Code(setup.SecretBase32, Now), Ct);

        Assert.NotNull(codes);
        Assert.Equal(RecoveryCodes.Count, codes.Count);
        Assert.Equal(codes.Count, codes.Distinct().Count());
        Assert.All(codes, c => Assert.Matches("^[a-z0-9]{5}-[a-z0-9]{5}$", c));
        Assert.True(await _service.IsEnabledAsync(Alice, Ct));
        var status = await _service.GetStatusAsync(Alice, Ct);
        Assert.Equal(TwoFactorState.On, status.State);
        Assert.Equal(10, status.RecoveryCodesLeft);
    }

    [Fact]
    public async Task The_code_of_the_confirmation_cannot_log_in_again()
    {
        var setup = await _service.BeginSetupAsync(Alice, "alice", Ct);
        var code = Code(setup.SecretBase32, Now);
        await _service.ConfirmSetupAsync(Alice, code, Ct);

        Assert.Equal(TwoFactorCheck.Replayed, await _service.VerifyAsync(Alice, code, Ct));
    }

    [Fact]
    public async Task The_stored_secret_is_encrypted()
    {
        var setup = await _service.BeginSetupAsync(Alice, "alice", Ct);

        var stored = await _store.GetAsync(Alice, Ct);
        Assert.NotNull(stored);
        Assert.DoesNotContain(setup.SecretBase32, stored.ProtectedSecret, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Convert.ToBase64String(Base32.Decode(setup.SecretBase32)!), stored.ProtectedSecret);
    }

    [Fact]
    public async Task A_valid_code_works_once()
    {
        var (secret, _) = await EnrolAsync(_service, Alice, _time);
        var code = Code(secret, Now);

        Assert.Equal(TwoFactorCheck.Valid, await _service.VerifyAsync(Alice, code, Ct));
        Assert.Equal(TwoFactorCheck.Replayed, await _service.VerifyAsync(Alice, code, Ct));

        _time.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(TwoFactorCheck.Replayed, await _service.VerifyAsync(Alice, code, Ct)); // still in the window, but used
        Assert.Equal(TwoFactorCheck.Valid, await _service.VerifyAsync(Alice, Code(secret, Now), Ct));
    }

    [Fact]
    public async Task An_older_code_is_refused_after_a_newer_one()
    {
        var (secret, _) = await EnrolAsync(_service, Alice, _time);

        Assert.Equal(TwoFactorCheck.Valid, await _service.VerifyAsync(Alice, Code(secret, Now, +1), Ct));
        Assert.Equal(TwoFactorCheck.Replayed, await _service.VerifyAsync(Alice, Code(secret, Now), Ct));
    }

    [Fact]
    public async Task One_step_of_clock_difference_is_accepted_and_two_are_not()
    {
        var (secret, _) = await EnrolAsync(_service, Alice, _time);

        Assert.Equal(TwoFactorCheck.Invalid, await _service.VerifyAsync(Alice, Code(secret, Now, +2), Ct));
        Assert.Equal(TwoFactorCheck.Valid, await _service.VerifyAsync(Alice, Code(secret, Now, +1), Ct));

        var late = await EnrolAsync(_service, Admin, _time);
        _time.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(TwoFactorCheck.Valid, await _service.VerifyAsync(Admin, Code(late.Secret, Now, -1), Ct));
    }

    [Fact]
    public async Task A_recovery_code_works_once()
    {
        var (_, codes) = await EnrolAsync(_service, Alice, _time);

        Assert.Equal(TwoFactorCheck.RecoveryCode, await _service.VerifyAsync(Alice, codes[3].ToUpperInvariant(), Ct));
        Assert.Equal(TwoFactorCheck.Invalid, await _service.VerifyAsync(Alice, codes[3], Ct));
        Assert.Equal(TwoFactorCheck.RecoveryCode, await _service.VerifyAsync(Alice, codes[4].Replace("-", ""), Ct));
        Assert.Equal(8, (await _service.GetStatusAsync(Alice, Ct)).RecoveryCodesLeft);
    }

    [Fact]
    public async Task The_recovery_codes_are_stored_as_pbkdf2_hashes()
    {
        var (_, codes) = await EnrolAsync(_service, Alice, _time);

        var stored = (await _store.GetAsync(Alice, Ct))!;
        Assert.Equal(10, stored.RecoveryCodeHashes.Count);
        Assert.All(stored.RecoveryCodeHashes, h => Assert.StartsWith("PBKDF2-SHA256.", h));
        Assert.All(codes, c => Assert.DoesNotContain(stored.RecoveryCodeHashes, h => h.Contains(c.Replace("-", ""), StringComparison.Ordinal)));
        // The format of the password hashes: each hash checks with the password hasher too.
        Assert.True(SshServer.Interfaces.Security.PasswordHasher.Verify(codes[0].Replace("-", ""), stored.RecoveryCodeHashes[0]));
    }

    [Fact]
    public async Task New_recovery_codes_replace_the_old_ones()
    {
        var (_, old) = await EnrolAsync(_service, Alice, _time);

        var fresh = await _service.RegenerateRecoveryCodesAsync(Alice, Ct);

        Assert.Equal(TwoFactorCheck.Invalid, await _service.VerifyAsync(Alice, old[0], Ct));
        Assert.Equal(TwoFactorCheck.RecoveryCode, await _service.VerifyAsync(Alice, fresh[0], Ct));
    }

    [Fact]
    public async Task Too_many_wrong_codes_lock_the_codes_of_the_subject_for_a_while()
    {
        var (secret, _) = await EnrolAsync(_service, Alice, _time);
        var (other, _) = await EnrolAsync(_service, Admin, _time);

        for (var i = 0; i < 5; i++)
            Assert.Equal(TwoFactorCheck.Invalid, await _service.VerifyAsync(Alice, "000000", Ct));

        // Even the right code is not checked now; another subject is not affected.
        Assert.Equal(TwoFactorCheck.LockedOut, await _service.VerifyAsync(Alice, Code(secret, Now), Ct));
        Assert.Equal(TwoFactorCheck.Valid, await _service.VerifyAsync(Admin, Code(other, Now), Ct));

        _time.Advance(TimeSpan.FromMinutes(5));
        Assert.Equal(TwoFactorCheck.Valid, await _service.VerifyAsync(Alice, Code(secret, Now), Ct));
    }

    [Fact]
    public async Task A_setup_cannot_start_again_while_the_second_factor_is_on()
    {
        await EnrolAsync(_service, Alice, _time);

        await Assert.ThrowsAsync<TwoFactorException>(() => _service.BeginSetupAsync(Alice, "alice", Ct));
    }

    [Fact]
    public async Task A_second_setup_replaces_an_unconfirmed_one()
    {
        var first = await _service.BeginSetupAsync(Alice, "alice", Ct);
        var second = await _service.BeginSetupAsync(Alice, "alice", Ct);

        Assert.NotEqual(first.SecretBase32, second.SecretBase32);
        Assert.Null(await _service.ConfirmSetupAsync(Alice, Code(first.SecretBase32, Now), Ct));
        Assert.NotNull(await _service.ConfirmSetupAsync(Alice, Code(second.SecretBase32, Now), Ct));
    }

    [Fact]
    public async Task The_reset_turns_the_second_factor_off()
    {
        var (secret, _) = await EnrolAsync(_service, Alice, _time);

        Assert.True(await _service.ResetAsync(Alice, Ct));

        Assert.False(await _service.IsEnabledAsync(Alice, Ct));
        Assert.Equal(TwoFactorCheck.NotEnabled, await _service.VerifyAsync(Alice, Code(secret, Now), Ct));
        Assert.False(await _service.ResetAsync(Alice, Ct));
    }

    [Fact]
    public async Task A_secret_that_cannot_be_decrypted_refuses_every_code()
    {
        var (secret, _) = await EnrolAsync(_service, Alice, _time);
        // Another key ring, as after a lost keys directory.
        var other = CreateService(_time, _store, new EphemeralDataProtectionProvider());

        Assert.Equal(TwoFactorCheck.Invalid, await other.VerifyAsync(Alice, Code(secret, Now), Ct));
        Assert.True(await other.IsEnabledAsync(Alice, Ct)); // still on: the login stays closed until a reset
    }

    [Fact]
    public async Task The_enabled_subjects_are_listed_per_kind()
    {
        await EnrolAsync(_service, Alice, _time);
        await _service.BeginSetupAsync(new TwoFactorSubject(TwoFactorSubjectKind.User, 8), "bob", Ct);

        Assert.Equal(new[] { 7 }, await _service.ListEnabledAsync(TwoFactorSubjectKind.User, Ct));
        Assert.Empty(await _service.ListEnabledAsync(TwoFactorSubjectKind.Admin, Ct));
    }

    [Fact]
    public void The_qr_code_is_an_svg_with_a_quiet_zone()
    {
        var svg = TotpQrCode.ToSvg("otpauth://totp/FreeSftpSharp:alice?secret=ABC");

        Assert.Matches("^<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 (\\d+) \\1\"", svg);
        Assert.Contains("<path fill=\"#000\" d=\"M", svg);
        Assert.DoesNotContain("http://", svg.Replace("http://www.w3.org/2000/svg", ""));
    }
}
