using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.TwoFactor;

namespace SshServer.TwoFactor;

/// <summary>The state of the second factor of a subject.</summary>
public enum TwoFactorState
{
    /// <summary>No second factor: the login is as before.</summary>
    Off,

    /// <summary>A secret is made, but not confirmed with a code yet: the login is as before.</summary>
    Pending,

    /// <summary>Confirmed: every login needs a code.</summary>
    On,
}

public sealed record TwoFactorStatus(TwoFactorState State, int RecoveryCodesLeft, DateTime? EnabledAt, DateTime? CreatedAt = null);

/// <summary>
/// A new secret for an authenticator app: the Base32 text for the manual entry, the <c>otpauth://</c> URI and its QR
/// code (SVG). Show it only to the person who sets up the app; it is never logged.
/// </summary>
public sealed record TwoFactorSetup(string SecretBase32, string OtpAuthUri, string QrCodeSvg);

/// <summary>A two-factor operation that is not possible now. The message is meant for the administrator.</summary>
public sealed class TwoFactorException : Exception
{
    public TwoFactorException(string message) : base(message)
    {
    }
}

/// <summary>
/// The TOTP second factor (issue #63, RFC 6238): enrolment with a confirmation code, the code check of the logins with
/// replay protection (a code works once, also across nodes, through the time step in the store), single-use recovery
/// codes, a per-subject limit for wrong codes, and the reset. The secrets are encrypted with
/// <see cref="TotpSecretProtector"/>. Codes and secrets are never logged.
/// <para>
/// The checks of who may do what are the caller's: the admin UI checks the permissions of the administrator first.
/// </para>
/// </summary>
public sealed class TwoFactorService : ITwoFactorVerifier
{
    /// <summary>How often an update is tried again when another login changed the enrolment at the same time.</summary>
    private const int UpdateAttempts = 5;

    private readonly ITwoFactorStore _store;
    private readonly TotpSecretProtector _protector;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly TwoFactorAttemptLimiter _limiter;
    private readonly string _issuer;

    public TwoFactorService(ITwoFactorStore store, TotpSecretProtector protector, IOptions<TwoFactorOptions> options,
        TimeProvider? time = null, ILogger<TwoFactorService>? logger = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        var settings = options?.Value ?? new TwoFactorOptions();
        _time = time ?? TimeProvider.System;
        _logger = (ILogger?)logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
        _limiter = new TwoFactorAttemptLimiter(_time, settings.MaxFailedCodes, TimeSpan.FromMinutes(settings.LockoutMinutes));
        _issuer = settings.Issuer.Trim();
    }

    public async Task<TwoFactorStatus> GetStatusAsync(TwoFactorSubject subject, CancellationToken ct)
    {
        var enrolment = await _store.GetAsync(subject, ct);
        return enrolment switch
        {
            null => new TwoFactorStatus(TwoFactorState.Off, 0, null),
            { Enabled: false } => new TwoFactorStatus(TwoFactorState.Pending, 0, null, enrolment.CreatedAt),
            _ => new TwoFactorStatus(TwoFactorState.On, enrolment.RecoveryCodeHashes.Count, enrolment.EnabledAt, enrolment.CreatedAt),
        };
    }

    public async Task<bool> IsEnabledAsync(TwoFactorSubject subject, CancellationToken ct) =>
        (await _store.GetAsync(subject, ct))?.Enabled == true;

    public Task<IReadOnlySet<int>> ListEnabledAsync(TwoFactorSubjectKind kind, CancellationToken ct) => _store.ListEnabledAsync(kind, ct);

    /// <summary>
    /// Makes a new secret (160 bits) for the subject and stores it unconfirmed; an unconfirmed one is replaced. The
    /// second factor is on only after <see cref="ConfirmSetupAsync"/>. Throws when it is on already (reset it first).
    /// </summary>
    /// <param name="accountName">The account name in the authenticator app, for example the user name.</param>
    public async Task<TwoFactorSetup> BeginSetupAsync(TwoFactorSubject subject, string accountName, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(accountName))
            throw new ArgumentException("The account name is empty.", nameof(accountName));
        var stored = await _store.GetAsync(subject, ct);
        if (stored?.Enabled == true)
            throw new TwoFactorException("Two-factor authentication is on already. Turn it off first to set up a new app.");

        var secret = RandomNumberGenerator.GetBytes(Totp.SecretSize);
        try
        {
            await _store.ReplaceAsync(new TwoFactorEnrolment
            {
                Subject = subject,
                ProtectedSecret = _protector.Protect(secret),
                CreatedAt = _time.GetUtcNow().UtcDateTime,
            }, ct);
            _logger.LogInformation("A new two-factor secret was made for {Subject}; it waits for the confirmation code.", subject);
            var base32 = Base32.Encode(secret);
            var uri = OtpAuthUri(accountName.Trim(), base32);
            return new TwoFactorSetup(base32, uri, TotpQrCode.ToSvg(uri));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>
    /// Turns the second factor on when <paramref name="code"/> is a valid code of the unconfirmed secret. Returns the
    /// new recovery codes (show them once), or null when the code is wrong. Throws when there is nothing to confirm.
    /// </summary>
    public async Task<IReadOnlyList<string>?> ConfirmSetupAsync(TwoFactorSubject subject, string? code, CancellationToken ct)
    {
        if (_limiter.IsLockedOut(subject))
            throw new TwoFactorException("Too many wrong codes. Try again later.");

        var enrolment = await _store.GetAsync(subject, ct);
        if (enrolment == null || enrolment.Enabled)
            throw new TwoFactorException("There is no new two-factor secret to confirm. Start the setup again.");

        var step = WithSecret(enrolment, (long?)null, secret => Totp.FindTimeStep(secret, code, _time.GetUtcNow(), long.MinValue));
        if (step == null)
        {
            _limiter.RecordFailure(subject);
            _logger.LogInformation("A wrong confirmation code was given for the two-factor setup of {Subject}.", subject);
            return null;
        }

        var codes = RecoveryCodes.Generate();
        var confirmed = enrolment with
        {
            Enabled = true,
            LastUsedStep = step.Value,
            RecoveryCodeHashes = RecoveryCodes.Hash(codes),
            EnabledAt = _time.GetUtcNow().UtcDateTime,
        };
        if (!await _store.TryUpdateAsync(confirmed, ct))
            throw new TwoFactorException("The two-factor setup was changed at the same time. Start the setup again.");

        _limiter.RecordSuccess(subject);
        _logger.LogInformation("Two-factor authentication is on for {Subject}.", subject);
        return codes;
    }

    public async Task<TwoFactorCheck> VerifyAsync(TwoFactorSubject subject, string? code, CancellationToken ct)
    {
        if (_limiter.IsLockedOut(subject))
            return TwoFactorCheck.LockedOut;

        var result = await CheckAsync(subject, code, ct);
        switch (result)
        {
            case TwoFactorCheck.Valid or TwoFactorCheck.RecoveryCode:
                _limiter.RecordSuccess(subject);
                break;
            case TwoFactorCheck.Invalid or TwoFactorCheck.Replayed:
                _limiter.RecordFailure(subject);
                break;
        }
        return result;
    }

    /// <summary>Replaces the recovery codes of a confirmed second factor; returns the new ones (show them once).</summary>
    public async Task<IReadOnlyList<string>> RegenerateRecoveryCodesAsync(TwoFactorSubject subject, CancellationToken ct)
    {
        for (var attempt = 0; attempt < UpdateAttempts; attempt++)
        {
            var enrolment = await _store.GetAsync(subject, ct);
            if (enrolment?.Enabled != true)
                throw new TwoFactorException("Two-factor authentication is not on.");
            var codes = RecoveryCodes.Generate();
            if (await _store.TryUpdateAsync(enrolment with { RecoveryCodeHashes = RecoveryCodes.Hash(codes) }, ct))
            {
                _logger.LogInformation("New recovery codes were made for {Subject}.", subject);
                return codes;
            }
        }
        throw new TwoFactorException("The two-factor settings were changed at the same time. Try again.");
    }

    /// <summary>Removes the second factor (confirmed or not) of the subject: the next login needs no code. False when there was none.</summary>
    public async Task<bool> ResetAsync(TwoFactorSubject subject, CancellationToken ct)
    {
        var removed = await _store.RemoveAsync(subject, ct);
        if (removed)
        {
            _limiter.RecordSuccess(subject);
            _logger.LogInformation("Two-factor authentication was turned off for {Subject}.", subject);
        }
        return removed;
    }

    private async Task<TwoFactorCheck> CheckAsync(TwoFactorSubject subject, string? code, CancellationToken ct)
    {
        var isTotp = Totp.Normalize(code) != null;
        var isRecovery = !isTotp && RecoveryCodes.Normalize(code) != null;

        for (var attempt = 0; attempt < UpdateAttempts; attempt++)
        {
            var enrolment = await _store.GetAsync(subject, ct);
            if (enrolment?.Enabled != true)
                return TwoFactorCheck.NotEnabled;

            if (isTotp)
            {
                var (step, usedBefore) = WithSecret(enrolment, ((long?)null, false), secret =>
                {
                    var now = _time.GetUtcNow();
                    var fresh = Totp.FindTimeStep(secret, code, now, enrolment.LastUsedStep);
                    return (fresh, fresh == null && Totp.FindTimeStep(secret, code, now, long.MinValue) != null);
                });
                if (step == null)
                    return usedBefore ? TwoFactorCheck.Replayed : TwoFactorCheck.Invalid;
                // Saved before the login goes on, so the same code cannot log in twice, also on another node.
                if (await _store.TryUpdateAsync(enrolment with { LastUsedStep = step.Value }, ct))
                    return TwoFactorCheck.Valid;
                continue; // another change came first: read again (a parallel login with the same code is then a replay)
            }

            if (isRecovery)
            {
                var index = RecoveryCodes.FindMatch(code, enrolment.RecoveryCodeHashes);
                if (index < 0)
                    return TwoFactorCheck.Invalid;
                var left = enrolment.RecoveryCodeHashes.Where((_, i) => i != index).ToList();
                if (await _store.TryUpdateAsync(enrolment with { RecoveryCodeHashes = left }, ct))
                {
                    _logger.LogWarning("A recovery code was used for {Subject}; {Left} recovery code(s) are left.", subject, left.Count);
                    return TwoFactorCheck.RecoveryCode;
                }
                continue;
            }

            return TwoFactorCheck.Invalid;
        }

        _logger.LogWarning("The second factor of {Subject} was changed too often at the same time; the code is refused.", subject);
        return TwoFactorCheck.Invalid;
    }

    /// <summary>
    /// Runs <paramref name="use"/> with the decrypted secret and clears it afterwards. When the secret cannot be
    /// decrypted, <paramref name="use"/> is not called and the result is <paramref name="failed"/> (fail closed).
    /// </summary>
    private T WithSecret<T>(TwoFactorEnrolment enrolment, T failed, Func<byte[], T> use)
    {
        var secret = _protector.TryUnprotect(enrolment.ProtectedSecret);
        if (secret == null || secret.Length == 0)
        {
            _logger.LogError(
                "The two-factor secret of {Subject} cannot be decrypted (other data protection keys?). Its codes are refused; reset its two-factor authentication.",
                enrolment.Subject);
            return failed;
        }
        try
        {
            return use(secret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private string OtpAuthUri(string accountName, string base32) =>
        $"otpauth://totp/{Uri.EscapeDataString(_issuer)}:{Uri.EscapeDataString(accountName)}" +
        $"?secret={base32}&issuer={Uri.EscapeDataString(_issuer)}&algorithm=SHA1&digits={Totp.Digits}&period={Totp.PeriodSeconds}";
}
