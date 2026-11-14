using System.Text;
using SshServer.Interfaces.TwoFactor;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>
/// The TOTP algorithm (issue #63): the known answers of RFC 6238 Appendix B and RFC 4226 Appendix D, the window of one
/// step before and after, the replay rule of the last used step, and Base32 (RFC 4648).
/// </summary>
public sealed class TotpTests
{
    private static readonly byte[] Sha1Seed = Encoding.ASCII.GetBytes("12345678901234567890");
    private static readonly byte[] Sha256Seed = Encoding.ASCII.GetBytes("12345678901234567890123456789012");
    private static readonly byte[] Sha512Seed = Encoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234");

    [Theory]
    [InlineData(59L, "94287082", TotpAlgorithm.Sha1)]
    [InlineData(59L, "46119246", TotpAlgorithm.Sha256)]
    [InlineData(59L, "90693936", TotpAlgorithm.Sha512)]
    [InlineData(1111111109L, "07081804", TotpAlgorithm.Sha1)]
    [InlineData(1111111109L, "68084774", TotpAlgorithm.Sha256)]
    [InlineData(1111111109L, "25091201", TotpAlgorithm.Sha512)]
    [InlineData(1111111111L, "14050471", TotpAlgorithm.Sha1)]
    [InlineData(1111111111L, "67062674", TotpAlgorithm.Sha256)]
    [InlineData(1111111111L, "99943326", TotpAlgorithm.Sha512)]
    [InlineData(1234567890L, "89005924", TotpAlgorithm.Sha1)]
    [InlineData(1234567890L, "91819424", TotpAlgorithm.Sha256)]
    [InlineData(1234567890L, "93441116", TotpAlgorithm.Sha512)]
    [InlineData(2000000000L, "69279037", TotpAlgorithm.Sha1)]
    [InlineData(2000000000L, "90698825", TotpAlgorithm.Sha256)]
    [InlineData(2000000000L, "38618901", TotpAlgorithm.Sha512)]
    [InlineData(20000000000L, "65353130", TotpAlgorithm.Sha1)]
    [InlineData(20000000000L, "77737706", TotpAlgorithm.Sha256)]
    [InlineData(20000000000L, "47863826", TotpAlgorithm.Sha512)]
    public void Rfc6238_appendix_b_test_vectors(long unixTime, string expected, TotpAlgorithm algorithm)
    {
        var seed = algorithm switch
        {
            TotpAlgorithm.Sha1 => Sha1Seed,
            TotpAlgorithm.Sha256 => Sha256Seed,
            _ => Sha512Seed,
        };
        var step = Totp.TimeStep(DateTimeOffset.FromUnixTimeSeconds(unixTime));

        Assert.Equal(expected, Totp.ComputeCode(seed, step, digits: 8, algorithm));
        // The 6-digit code of the server is the same value modulo 10^6.
        Assert.Equal(expected[2..], Totp.ComputeCode(seed, step, algorithm: algorithm));
    }

    [Theory]
    [InlineData(0, "755224")]
    [InlineData(1, "287082")]
    [InlineData(2, "359152")]
    [InlineData(3, "969429")]
    [InlineData(4, "338314")]
    [InlineData(5, "254676")]
    [InlineData(6, "287922")]
    [InlineData(7, "162583")]
    [InlineData(8, "399871")]
    [InlineData(9, "520489")]
    public void Rfc4226_appendix_d_hotp_values(long counter, string expected)
    {
        Assert.Equal(expected, Totp.ComputeCode(Sha1Seed, counter));
    }

    [Fact]
    public void Time_steps_are_30_seconds_from_the_epoch()
    {
        Assert.Equal(0, Totp.TimeStep(DateTimeOffset.FromUnixTimeSeconds(29)));
        Assert.Equal(1, Totp.TimeStep(DateTimeOffset.FromUnixTimeSeconds(30)));
        Assert.Equal(37037036, Totp.TimeStep(DateTimeOffset.FromUnixTimeSeconds(1111111109)));
    }

    [Fact]
    public void A_code_of_the_current_step_or_one_step_before_or_after_is_found()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_015);
        var current = Totp.TimeStep(now);

        foreach (var offset in new[] { -1, 0, 1 })
            Assert.Equal(current + offset, Totp.FindTimeStep(Sha1Seed, Totp.ComputeCode(Sha1Seed, current + offset), now, long.MinValue));
        foreach (var offset in new[] { -3, -2, 2, 3 })
            Assert.Null(Totp.FindTimeStep(Sha1Seed, Totp.ComputeCode(Sha1Seed, current + offset), now, long.MinValue));
    }

    [Fact]
    public void A_code_of_the_last_used_step_or_an_older_one_is_not_found()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_015);
        var current = Totp.TimeStep(now);
        var code = Totp.ComputeCode(Sha1Seed, current);

        Assert.Null(Totp.FindTimeStep(Sha1Seed, code, now, lastUsedStep: current));
        Assert.Null(Totp.FindTimeStep(Sha1Seed, Totp.ComputeCode(Sha1Seed, current - 1), now, lastUsedStep: current));
        Assert.Equal(current + 1, Totp.FindTimeStep(Sha1Seed, Totp.ComputeCode(Sha1Seed, current + 1), now, lastUsedStep: current));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12a456")]
    [InlineData("１２３４５６")] // full-width digits are not ASCII digits
    public void A_code_that_is_not_six_digits_is_not_found(string? code)
    {
        Assert.Null(Totp.FindTimeStep(Sha1Seed, code, DateTimeOffset.UtcNow, long.MinValue));
    }

    [Fact]
    public void Spaces_in_a_typed_code_are_ignored()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_015);
        var code = Totp.ComputeCode(Sha1Seed, Totp.TimeStep(now));

        Assert.NotNull(Totp.FindTimeStep(Sha1Seed, $" {code[..3]} {code[3..]} ", now, long.MinValue));
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("f", "MY")]
    [InlineData("fo", "MZXQ")]
    [InlineData("foo", "MZXW6")]
    [InlineData("foob", "MZXW6YQ")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI")]
    public void Base32_matches_rfc4648(string text, string encoded)
    {
        var bytes = Encoding.ASCII.GetBytes(text);

        Assert.Equal(encoded, Base32.Encode(bytes));
        Assert.Equal(bytes, Base32.Decode(encoded));
        Assert.Equal(bytes, Base32.Decode(encoded.ToLowerInvariant() + "===="));
    }

    [Fact]
    public void Base32_refuses_other_characters()
    {
        Assert.Null(Base32.Decode("MZXW1"));
        Assert.Null(Base32.Decode(null));
    }
}
