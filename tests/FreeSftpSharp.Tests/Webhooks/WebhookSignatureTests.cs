using System.Security.Cryptography;
using System.Text;
using SshServer.Webhooks;

namespace FreeSftpSharp.Tests.Webhooks;

/// <summary>The signature header: t=&lt;unix&gt;,v1=&lt;hex HMAC-SHA256(secret, t + "." + body)&gt;, and its check by a receiver.</summary>
public sealed class WebhookSignatureTests
{
    private const string Secret = "0123456789abcdef-test-secret";
    private const string Body = "{\"event\":\"File.Upload\"}";
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

    [Fact]
    public void The_header_has_the_time_and_the_hmac_of_time_dot_body()
    {
        var header = WebhookSignature.Create(Secret, 1_800_000_000, Body);

        var expected = Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(Secret), Encoding.UTF8.GetBytes("1800000000." + Body)));
        Assert.Equal("t=1800000000,v1=" + expected, header);
        Assert.Matches("^t=[0-9]+,v1=[0-9a-f]{64}$", header);
    }

    [Fact]
    public void A_receiver_accepts_the_signature_and_refuses_a_changed_body_another_secret_and_an_old_time()
    {
        var header = WebhookSignature.Create(Secret, Now.ToUnixTimeSeconds(), Body);
        var tolerance = TimeSpan.FromMinutes(5);

        Assert.True(WebhookSignature.Verify(Secret, header, Body, Now, tolerance));
        Assert.False(WebhookSignature.Verify(Secret, header, Body + " ", Now, tolerance));
        Assert.False(WebhookSignature.Verify("another-secret-0123456789", header, Body, Now, tolerance));
        Assert.False(WebhookSignature.Verify(Secret, header, Body, Now.AddMinutes(6), tolerance));
        Assert.False(WebhookSignature.Verify(Secret, null, Body, Now, tolerance));
        Assert.False(WebhookSignature.Verify(Secret, "v1=" + WebhookSignature.ComputeV1(Secret, Now.ToUnixTimeSeconds(), Body), Body, Now, tolerance));
    }
}
