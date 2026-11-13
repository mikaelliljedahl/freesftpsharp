using System.Text;
using static FreeSftpSharp.Tests.Sftp.SftpEngineClient;

namespace FreeSftpSharp.Tests.Sftp;

/// <summary>
/// Framing of the SFTP engine: a packet can come in several channel data messages, and one channel data
/// message can contain several packets (OpenSSH sftp sends requests without waiting for the responses).
/// Every request gets exactly one response. Ported from the tests of the old SftpSubsystem.
/// </summary>
public sealed class SftpFramingTests : SftpEngineTestBase
{
    public SftpFramingTests()
    {
        Directory.CreateDirectory(Physical("/dir"));
    }

    [Fact]
    public void Init_gives_one_version_response_with_version_3()
    {
        Client.Service.OnData(Init(6));

        var response = Response.Parse(Assert.Single(Client.Responses));
        Assert.Equal(SSH_FXP_VERSION, response.Type);
        Assert.Equal(3u, response.Payload.ReadUInt32());
    }

    [Fact]
    public void Init_split_into_single_bytes_gives_one_response()
    {
        foreach (var b in Init())
            Client.Service.OnData(new[] { b });

        Assert.Equal(SSH_FXP_VERSION, Response.Parse(Assert.Single(Client.Responses)).Type);
    }

    [Fact]
    public void Packet_split_over_several_calls_gives_one_response()
    {
        var packet = PathRequest(SSH_FXP_REALPATH, 7, "/dir/../dir/.");

        Client.Service.OnData(packet[..2]);    // part of the length
        Client.Service.OnData(packet[2..6]);   // rest of the length, type, part of the id
        Assert.Empty(Client.Responses);
        Client.Service.OnData(packet[6..^3]);
        Assert.Empty(Client.Responses);
        Client.Service.OnData(packet[^3..]);

        var response = Response.Parse(Assert.Single(Client.Responses));
        Assert.Equal(7u, response.Id);
        Assert.Equal("/dir", Assert.Single(response.Names()).Name);
    }

    [Fact]
    public void Several_packets_in_one_call_give_one_response_each_in_order()
    {
        var data = Concat(
            PathRequest(SSH_FXP_REALPATH, 1, "."),
            PathRequest(SSH_FXP_STAT, 2, "/dir"),
            PathRequest(SSH_FXP_STAT, 3, "/missing"),
            PathRequest(SSH_FXP_REALPATH, 4, "/a/../.."));

        Client.Service.OnData(data);

        var responses = Client.Responses.Select(Response.Parse).ToList();
        Assert.Equal([1u, 2u, 3u, 4u], responses.Select(r => r.Id));
        Assert.Equal("/", Assert.Single(responses[0].Names()).Name);
        Assert.Equal(SSH_FXP_ATTRS, responses[1].Type);
        Assert.Equal(SSH_FX_NO_SUCH_FILE, responses[2].StatusCode);
        Assert.Equal("/", Assert.Single(responses[3].Names()).Name);
    }

    [Fact]
    public void Complete_packets_are_answered_and_a_partial_packet_waits_for_the_rest()
    {
        var second = PathRequest(SSH_FXP_STAT, 2, "/dir");

        Client.Service.OnData(Concat(PathRequest(SSH_FXP_REALPATH, 1, "/"), second[..5]));
        Assert.Single(Client.Responses);

        Client.Service.OnData(second[5..]);
        Assert.Equal(2, Client.Responses.Count);
        var response = Response.Parse(Client.Responses[1]);
        Assert.Equal(SSH_FXP_ATTRS, response.Type);
        Assert.Equal(2u, response.Id);
    }

    [Fact]
    public void Every_response_has_a_correct_length_prefix()
    {
        Client.Service.OnData(Concat(PathRequest(SSH_FXP_REALPATH, 1, "/"), PathRequest(SSH_FXP_STAT, 2, "/dir"), PathRequest(SSH_FXP_STAT, 3, "/missing")));

        Assert.Equal(3, Client.Responses.Count);
        foreach (var response in Client.Responses)
            Response.Parse(response); // checks the length prefix
    }

    [Fact]
    public void Invalid_frame_length_discards_the_data_and_the_session_continues()
    {
        Client.Service.OnData(new byte[] { 0, 0, 0, 0, 1, 2, 3 });         // length 0
        Client.Service.OnData(new byte[] { 0x7F, 0xFF, 0xFF, 0xFF, 17 });  // larger than the engine accepts
        Assert.Empty(Client.Responses);

        Assert.Equal("/dir", Client.RealPath("/dir"));
    }

    [Fact]
    public void A_request_with_missing_fields_gets_an_error_status_with_its_id()
    {
        // STAT without the path string.
        var response = Client.Send(Request(SSH_FXP_STAT, 42));

        Assert.Equal(42u, response.Id);
        Assert.NotEqual(SSH_FX_OK, response.StatusCode);
        Assert.Equal("/dir", Client.RealPath("/dir"));
    }

    private static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();
}
