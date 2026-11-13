using System.Security.Cryptography;
using FreeSftpSharp.Tests.Infrastructure;
using static FreeSftpSharp.Tests.Infrastructure.OpenSshSftp;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// End-to-end tests with the OpenSSH sftp client. They are skipped when sftp is not on PATH.
/// Every test ends with "pwd", so a "Remote working directory" line proves that the session ran to the end.
/// </summary>
public sealed class OpenSshSftpTests : IClassFixture<SftpServerFixture>
{
    private const string SessionEndMarker = "Remote working directory: /";

    private readonly SftpServerFixture _server;

    public OpenSshSftpTests(SftpServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task Put_and_get_of_2MB_200B_and_0B_files_give_the_same_bytes()
    {
        SkipIfUnavailable();
        var local = CreateLocalDirectory();
        var remote = _server.CreateUniqueDirectory("ossh");
        var files = new Dictionary<string, byte[]>
        {
            ["big.bin"] = RandomNumberGenerator.GetBytes(2 * 1024 * 1024),
            ["small.bin"] = RandomNumberGenerator.GetBytes(200),
            ["empty.bin"] = Array.Empty<byte>(),
        };
        foreach (var (name, data) in files)
            File.WriteAllBytes(Path.Combine(local, name), data);

        var commands = new List<string> { "cd " + remote };
        foreach (var name in files.Keys)
            commands.Add($"put {Quote(Path.Combine(local, name))} {name}");
        foreach (var name in files.Keys)
            commands.Add($"get {name} {Quote(Path.Combine(local, name + ".down"))}");
        commands.Add("pwd");

        var result = await RunAsync(_server, local, commands.ToArray());

        AssertSessionCompleted(result);
        foreach (var (name, data) in files)
        {
            Assert.True(data.AsSpan().SequenceEqual(File.ReadAllBytes(_server.PhysicalPath(remote + "/" + name))),
                $"Uploaded {name} differs on the server.{Environment.NewLine}{result}");
            Assert.True(data.AsSpan().SequenceEqual(File.ReadAllBytes(Path.Combine(local, name + ".down"))),
                $"Downloaded {name} differs.{Environment.NewLine}{result}");
        }
    }

    [Fact]
    public async Task Ls_lists_the_files_of_a_directory()
    {
        SkipIfUnavailable();
        var remote = _server.CreateUniqueDirectory("ossh");
        File.WriteAllText(_server.PhysicalPath(remote + "/first.txt"), "1");
        File.WriteAllText(_server.PhysicalPath(remote + "/second.txt"), "2");

        var result = await RunAsync(_server, CreateLocalDirectory(), "ls -1 " + remote, "pwd");

        AssertSessionCompleted(result);
        Assert.Contains("first.txt", result.StandardOutput);
        Assert.Contains("second.txt", result.StandardOutput);
    }

    [Fact]
    public async Task Rename_moves_a_file()
    {
        SkipIfUnavailable();
        var remote = _server.CreateUniqueDirectory("ossh");
        File.WriteAllText(_server.PhysicalPath(remote + "/old.txt"), "content");

        var result = await RunAsync(_server, CreateLocalDirectory(), $"rename {remote}/old.txt {remote}/new.txt", "pwd");

        AssertSessionCompleted(result);
        Assert.False(File.Exists(_server.PhysicalPath(remote + "/old.txt")), result.ToString());
        Assert.Equal("content", File.ReadAllText(_server.PhysicalPath(remote + "/new.txt")));
    }

    [Fact]
    public async Task Rm_removes_a_file()
    {
        SkipIfUnavailable();
        var remote = _server.CreateUniqueDirectory("ossh");
        File.WriteAllText(_server.PhysicalPath(remote + "/gone.txt"), "x");

        var result = await RunAsync(_server, CreateLocalDirectory(), $"rm {remote}/gone.txt", "pwd");

        AssertSessionCompleted(result);
        Assert.False(File.Exists(_server.PhysicalPath(remote + "/gone.txt")), result.ToString());
    }

    [Fact]
    public async Task Rmdir_removes_an_empty_directory()
    {
        SkipIfUnavailable();
        var remote = _server.CreateUniqueDirectory("ossh");

        var result = await RunAsync(_server, CreateLocalDirectory(), "rmdir " + remote, "pwd");

        AssertSessionCompleted(result);
        Assert.False(Directory.Exists(_server.PhysicalPath(remote)), result.ToString());
    }

    [Fact]
    public async Task Cd_up_twice_from_the_root_then_pwd_gives_the_root()
    {
        SkipIfUnavailable();

        var result = await RunAsync(_server, CreateLocalDirectory(), "cd ../..", "pwd");

        AssertSessionCompleted(result);
        Assert.Matches(@"Remote working directory: /\r?$", result.StandardOutput.Split('\n').First(l => l.Contains("Remote working directory")));
    }

    [Fact]
    public async Task Overwrite_of_a_2MB_file_with_a_200B_file_gives_200B()
    {
        SkipIfUnavailable();
        var local = CreateLocalDirectory();
        var remote = _server.CreateUniqueDirectory("ossh");
        var big = RandomNumberGenerator.GetBytes(2 * 1024 * 1024);
        var small = RandomNumberGenerator.GetBytes(200);
        File.WriteAllBytes(Path.Combine(local, "big.bin"), big);
        File.WriteAllBytes(Path.Combine(local, "small.bin"), small);

        var result = await RunAsync(_server, local,
            "cd " + remote,
            $"put {Quote(Path.Combine(local, "big.bin"))} target.bin",
            $"put {Quote(Path.Combine(local, "small.bin"))} target.bin",
            $"get target.bin {Quote(Path.Combine(local, "target.down"))}",
            "pwd");

        AssertSessionCompleted(result);
        Assert.Equal(200, new FileInfo(_server.PhysicalPath(remote + "/target.bin")).Length);
        Assert.Equal(small, File.ReadAllBytes(Path.Combine(local, "target.down")));
    }

    [Fact]
    public async Task Get_of_the_config_db_outside_the_root_fails()
    {
        SkipIfUnavailable();
        var local = CreateLocalDirectory();
        var target = Path.Combine(local, "stolen.db");

        var result = await RunAsync(_server, local, $"get ../../config.db {Quote(target)}", "pwd");

        AssertSessionCompleted(result);
        Assert.False(File.Exists(target), $"config.db outside the user root was downloaded.{Environment.NewLine}{result}");
        Assert.DoesNotContain(SftpServerFixture.SecretContent, result.AllOutput);
    }

    [Fact]
    public async Task Sftp_exits_by_itself_after_the_last_command()
    {
        SkipIfUnavailable();

        var result = await RunAsync(_server, CreateLocalDirectory(), TimeSpan.FromSeconds(10), "pwd");

        AssertSessionCompleted(result);
        Assert.True(result.ExitedByItself, result.ToString());
        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public async Task OpenSsh_connects_with_its_default_algorithms_and_a_sha2_or_ecdsa_host_key()
    {
        SkipIfUnavailable();

        // No HostKeyAlgorithms=+ssh-rsa: the OpenSSH defaults must work.
        var result = await RunWithOptionsAsync(_server, CreateLocalDirectory(), new[] { "LogLevel=DEBUG" }, "pwd");

        AssertSessionCompleted(result);
        var hostKey = DebugValue(result, "kex: host key algorithm: ");
        Assert.True(hostKey is "ecdsa-sha2-nistp256" or "rsa-sha2-512" or "rsa-sha2-256", $"host key algorithm: {hostKey}{Environment.NewLine}{result}");
        Assert.DoesNotContain("connection is not using a post-quantum key exchange", result.AllOutput);
    }

    [Fact]
    public async Task OpenSsh_that_knows_the_old_rsa_host_key_still_accepts_the_server()
    {
        SkipIfUnavailable();
        // A client that connected to an older version has the RSA key as "ssh-rsa" in known_hosts.
        // The key did not change; only the signature is SHA-2 now, so strict host key checking passes.
        var knownHosts = Path.Combine(_server.TempDirectory, "known_hosts-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(knownHosts, $"[{SftpServerFixture.Host}]:{_server.Port} ssh-rsa {SshRsaPublicKey(TestCredentials.HostKey)}\n");

        var result = await RunWithOptionsAsync(_server, CreateLocalDirectory(),
            new[] { "StrictHostKeyChecking=yes", "UserKnownHostsFile=" + knownHosts, "LogLevel=DEBUG" }, "pwd");

        AssertSessionCompleted(result);
        Assert.StartsWith("rsa-sha2-", DebugValue(result, "kex: host key algorithm: "));
    }

    /// <summary>The base64 "ssh-rsa" public key blob (RFC 4253 section 6.6) of a base64 CSP blob.</summary>
    private static string SshRsaPublicKey(string cspBlob)
    {
        using var csp = new RSACryptoServiceProvider();
        csp.ImportCspBlob(Convert.FromBase64String(cspBlob));
        var parameters = csp.ExportParameters(false);
        using var blob = new MemoryStream();
        foreach (var part in new[] { "ssh-rsa"u8.ToArray(), Mpint(parameters.Exponent!), Mpint(parameters.Modulus!) })
        {
            blob.Write(new[] { (byte)(part.Length >> 24), (byte)(part.Length >> 16), (byte)(part.Length >> 8), (byte)part.Length });
            blob.Write(part);
        }
        return Convert.ToBase64String(blob.ToArray());

        static byte[] Mpint(byte[] value) => (value[0] & 0x80) != 0 ? new byte[] { 0 }.Concat(value).ToArray() : value;
    }

    [Fact]
    public async Task OpenSsh_cannot_connect_when_it_allows_only_ssh_rsa_sha1_signatures()
    {
        SkipIfUnavailable();

        var result = await RunWithOptionsAsync(_server, CreateLocalDirectory(), new[] { "HostKeyAlgorithms=ssh-rsa" }, "pwd");

        AssertNegotiationFailed(result);
    }

    [Theory]
    [InlineData("KexAlgorithms=diffie-hellman-group1-sha1")]
    [InlineData("KexAlgorithms=diffie-hellman-group14-sha1")]
    [InlineData("MACs=hmac-md5,hmac-sha1")]
    [InlineData("Ciphers=aes128-cbc,aes256-cbc,3des-cbc")]
    public async Task OpenSsh_cannot_connect_with_only_weak_algorithms(string option)
    {
        SkipIfUnavailable();

        // MACs only matter for a non-AEAD cipher.
        var options = option.StartsWith("MACs=", StringComparison.Ordinal)
            ? new[] { option, "Ciphers=aes256-ctr" }
            : new[] { option };
        var result = await RunWithOptionsAsync(_server, CreateLocalDirectory(), options, "pwd");

        AssertNegotiationFailed(result);
    }

    /// <summary>
    /// The server closes the connection when no algorithm matches (OpenSSH then prints "Connection closed",
    /// or "Unable to negotiate ..." when it sees the mismatch first). The password prompt is never reached.
    /// </summary>
    private static void AssertNegotiationFailed(Result result)
    {
        Assert.DoesNotContain(SessionEndMarker, result.StandardOutput);
        Assert.True(result.ExitedByItself && result.ExitCode != 0, result.ToString());
        Assert.True(result.StandardError.Contains("Connection closed", StringComparison.Ordinal) ||
                    result.StandardError.Contains("Unable to negotiate", StringComparison.Ordinal), result.ToString());
        Assert.DoesNotContain("Permission denied", result.StandardError);
    }

    private static string? DebugValue(Result result, string prefix)
    {
        var line = result.StandardError.Split('\n').FirstOrDefault(l => l.Contains(prefix, StringComparison.Ordinal));
        return line?[(line.IndexOf(prefix, StringComparison.Ordinal) + prefix.Length)..].Trim();
    }

    private string CreateLocalDirectory()
    {
        var local = Path.Combine(_server.TempDirectory, "local-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(local);
        return local;
    }

    private static void AssertSessionCompleted(Result result)
    {
        Assert.True(result.StandardOutput.Contains(SessionEndMarker), $"The sftp session did not run to the end.{Environment.NewLine}{result}");
    }
}
