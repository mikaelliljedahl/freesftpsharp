using System.Net;
using FreeSftpSharp.Tests.Infrastructure;
using FxSsh.SshServerModule;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>
/// <see cref="UserLogics"/>: public key authentication by the whole key blob (issue #58) and the IP whitelist (passwords: UserPasswordVerificationTests).
/// </summary>
public sealed class UserLogicsTests
{
    private static readonly DateTime Now = new(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);

    private static User UserWith(params PublicKeyEntry[] keys) => new() { Username = "u", PublicKeys = keys.ToList() };

    [Fact]
    public void Each_key_of_the_user_is_accepted()
    {
        var ed25519 = TestUserKeys.Ed25519();
        var rsa = TestUserKeys.Rsa();
        var user = UserWith(ed25519.Entry, rsa.Entry);

        Assert.True(UserLogics.VerifyUserKey(user, ed25519.Blob, Now));
        Assert.True(UserLogics.VerifyUserKey(user, rsa.Blob, Now));
    }

    [Fact]
    public void A_key_that_is_not_in_the_list_is_rejected()
    {
        var user = UserWith(TestUserKeys.Ed25519().Entry, TestUserKeys.Rsa().Entry);

        Assert.False(UserLogics.VerifyUserKey(user, TestUserKeys.Ed25519().Blob, Now));
        Assert.False(UserLogics.VerifyUserKey(user, TestUserKeys.Rsa().Blob, Now));
    }

    [Fact]
    public void A_key_with_the_same_fingerprint_but_another_blob_is_rejected()
    {
        // The stored entry claims the fingerprint of the client key, but its blob is another key: only the blob counts.
        var client = TestUserKeys.Ed25519();
        var stored = TestUserKeys.Ed25519().Entry;
        stored.Fingerprint = client.Entry.Fingerprint;

        Assert.False(UserLogics.VerifyUserKey(UserWith(stored), client.Blob, Now));
    }

    [Fact]
    public void An_expired_key_is_rejected_and_a_key_before_its_expiry_is_accepted()
    {
        var key = TestUserKeys.Ed25519();
        key.Entry.ExpiresAt = Now;
        var user = UserWith(key.Entry);

        Assert.False(UserLogics.VerifyUserKey(user, key.Blob, Now));
        Assert.True(UserLogics.VerifyUserKey(user, key.Blob, Now.AddSeconds(-1)));
    }

    [Fact]
    public void A_user_without_keys_or_an_empty_request_is_rejected()
    {
        var key = TestUserKeys.Ed25519();

        Assert.False(UserLogics.VerifyUserKey(new User { Username = "u" }, key.Blob, Now));
        Assert.False(UserLogics.VerifyUserKey(UserWith(), key.Blob, Now));
        Assert.False(UserLogics.VerifyUserKey(UserWith(key.Entry), Array.Empty<byte>(), Now));
        Assert.False(UserLogics.VerifyUserKey(UserWith(key.Entry), null!, Now));
        Assert.False(UserLogics.VerifyUserKey(UserWith(new PublicKeyEntry { KeyBase64 = "broken!" }), key.Blob, Now));
    }

    [Theory]
    [InlineData("192.168.1.5", true)]
    [InlineData("::ffff:192.168.1.5", true)]   // an IPv4 client on the dual-stack listener
    [InlineData("10.0.0.1", false)]
    [InlineData("::ffff:10.0.0.1", false)]
    public void Ip_whitelist_is_checked_for_ipv4_and_ipv4_mapped_addresses(string address, bool allowed)
    {
        var user = new User
        {
            Username = "u",
            OnlyWhitelistedIps = true,
            WhitelistedIps = new List<string> { "192.168.0.0/16" },
        };

        Assert.Equal(allowed, UserLogics.VerifyUserIpWhitelisted(user, new IPEndPoint(IPAddress.Parse(address), 50000)));
    }

    [Fact]
    public void Without_a_whitelist_every_address_is_allowed()
    {
        var user = new User { Username = "u", OnlyWhitelistedIps = false };

        Assert.True(UserLogics.VerifyUserIpWhitelisted(user, new IPEndPoint(IPAddress.Parse("10.0.0.1"), 50000)));
    }
}
