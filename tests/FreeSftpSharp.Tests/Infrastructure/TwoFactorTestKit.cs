using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.TwoFactor;
using SshServer.TwoFactor;

namespace FreeSftpSharp.Tests.Infrastructure;

/// <summary>Builds the TOTP service of the tests and computes the codes an authenticator app would show.</summary>
public static class TwoFactorTestKit
{
    public static TwoFactorService CreateService(TimeProvider time, ITwoFactorStore? store = null, IDataProtectionProvider? protection = null,
        int maxFailedCodes = 5) =>
        new(store ?? new InMemoryTwoFactorStore(),
            new TotpSecretProtector(protection ?? new EphemeralDataProtectionProvider()),
            Options.Create(new TwoFactorOptions { MaxFailedCodes = maxFailedCodes }),
            time);

    /// <summary>The code of the Base32 secret at <paramref name="time"/>, plus <paramref name="steps"/> time steps.</summary>
    public static string Code(string secretBase32, DateTimeOffset time, int steps = 0) =>
        Totp.ComputeCode(Base32.Decode(secretBase32)!, Totp.TimeStep(time) + steps);

    /// <summary>Sets up and confirms a second factor; returns the secret and the recovery codes.</summary>
    public static async Task<(string Secret, IReadOnlyList<string> RecoveryCodes)> EnrolAsync(TwoFactorService service, TwoFactorSubject subject,
        TimeProvider time, string account = "account")
    {
        var setup = await service.BeginSetupAsync(subject, account, CancellationToken.None);
        // The confirmation uses the code of the previous step, so the current one is still unused for the first login.
        var codes = await service.ConfirmSetupAsync(subject, Code(setup.SecretBase32, time.GetUtcNow(), -1), CancellationToken.None)
                    ?? throw new InvalidOperationException("The confirmation code was refused.");
        return (setup.SecretBase32, codes);
    }
}
