using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.Unit;

public sealed class PasswordHasherTests
{
    // The minimum keeps the tests fast; production hashes use DefaultIterations.
    private const int Iterations = PasswordHasher.MinimumIterations;

    [Fact]
    public void Hash_then_verify_with_the_same_password_succeeds()
    {
        var hash = PasswordHasher.Hash("correct horse battery staple", Iterations);

        Assert.True(PasswordHasher.Verify("correct horse battery staple", hash));
    }

    [Fact]
    public void Verify_with_a_wrong_password_fails()
    {
        var hash = PasswordHasher.Hash("correct horse battery staple", Iterations);

        Assert.False(PasswordHasher.Verify("correct horse battery stapl", hash));
        Assert.False(PasswordHasher.Verify("Correct horse battery staple", hash));
        Assert.False(PasswordHasher.Verify("", hash));
    }

    [Fact]
    public void Hash_uses_pbkdf2_sha256_with_at_least_100k_iterations_by_default()
    {
        var hash = PasswordHasher.Hash("secret");
        var parts = hash.Split('.');

        Assert.Equal(4, parts.Length);
        Assert.Equal("PBKDF2-SHA256", parts[0]);
        Assert.True(int.Parse(parts[1]) >= 100_000);
        Assert.Equal(PasswordHasher.DefaultIterations, int.Parse(parts[1]));
        Assert.DoesNotContain("secret", hash);
        Assert.True(PasswordHasher.Verify("secret", hash));
    }

    [Fact]
    public void Two_hashes_of_the_same_password_have_different_salts()
    {
        var first = PasswordHasher.Hash("secret", Iterations);
        var second = PasswordHasher.Hash("secret", Iterations);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Hash_rejects_fewer_than_the_minimum_iterations()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => PasswordHasher.Hash("secret", 1000));
    }

    [Theory]
    [InlineData(3)] // derived key
    [InlineData(2)] // salt
    public void Verify_fails_when_a_byte_of_the_hash_is_changed(int partIndex)
    {
        var hash = PasswordHasher.Hash("secret", Iterations);
        var parts = hash.Split('.');
        var bytes = Convert.FromBase64String(parts[partIndex]);
        bytes[0] ^= 0x01;
        parts[partIndex] = Convert.ToBase64String(bytes);

        Assert.False(PasswordHasher.Verify("secret", string.Join('.', parts)));
    }

    [Fact]
    public void Verify_fails_when_the_iteration_count_is_changed()
    {
        var hash = PasswordHasher.Hash("secret", Iterations);
        var tampered = hash.Replace($".{Iterations}.", $".{Iterations + 1}.");

        Assert.False(PasswordHasher.Verify("secret", tampered));
    }

    [Fact]
    public void Verify_fails_when_the_derived_key_is_truncated()
    {
        var hash = PasswordHasher.Hash("secret", Iterations);
        var parts = hash.Split('.');
        parts[3] = Convert.ToBase64String(Convert.FromBase64String(parts[3])[..16]);

        Assert.False(PasswordHasher.Verify("secret", string.Join('.', parts)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("secret")] // a plaintext password in the config is not a hash
    [InlineData("PBKDF2-SHA256.100000.notbase64!.AAAA")]
    [InlineData("PBKDF2-SHA1.100000.AAAAAAAAAAAAAAAAAAAAAA==.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("PBKDF2-SHA256.1000.AAAAAAAAAAAAAAAAAAAAAA==.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("PBKDF2-SHA256.abc.AAAAAAAAAAAAAAAAAAAAAA==.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("PBKDF2-SHA256.100000.AAAAAAAAAAAAAAAAAAAAAA==")]
    public void Malformed_hashes_are_not_well_formed_and_never_verify(string? encoded)
    {
        Assert.False(PasswordHasher.IsWellFormed(encoded));
        Assert.False(PasswordHasher.Verify("secret", encoded));
    }

    [Fact]
    public void A_generated_hash_is_well_formed()
    {
        Assert.True(PasswordHasher.IsWellFormed(PasswordHasher.Hash("secret", Iterations)));
    }
}
