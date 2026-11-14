using System.Security.Cryptography;
using SshServer.Filesystem.Encrypted;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage.Encrypted;

/// <summary>
/// Known-answer vectors of the file format v1 (docs/ENCRYPTED-STORAGE.md). They were made with an independent
/// implementation (Python, AES and GCM written from the specifications and checked against FIPS-197, the GCM test cases
/// and RFC 5869), not with this code. If a test here fails, the format changed: files on disk would not be readable.
/// Master key 0x00..0x1f, key id "kat-key-1", salt 0x40..0x5f, pattern byte i = (i * 31 + 7) mod 256.
/// </summary>
public sealed class EncryptedFileFormatTests : IDisposable
{
    private const string KatKeyIdHex = "baf3a8c3e0dd35c6e0ef9609d336e282";
    private const string KatFileKeyHex = "aa18275d72a76470c6e5c805dba1e0fd7f813264b7b4cc7da615daf6a47e553f";
    private const string KatHeaderHex = "4653533101baf3a8c3e0dd35c6e0ef9609d336e282404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
    private const string KatHelloFileHex = KatHeaderHex + "48b5ffb0af9d2eb363a205c3820e28d2cdfb27a312";
    private const string KatEmptyFileHex = KatHeaderHex + "51796a85fb45d1d9d7a6c03a95f2d4be";

    private static readonly byte[] KatSalt = Enumerable.Range(0x40, 32).Select(i => (byte)i).ToArray();

    private readonly string _root = Path.Combine(Path.GetTempPath(), "freesftpsharp-tests", Guid.NewGuid().ToString("N"));

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public EncryptedFileFormatTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    [Fact]
    public void Key_id_is_the_first_16_bytes_of_sha256_of_the_id()
    {
        Assert.Equal(KatKeyIdHex, Convert.ToHexStringLower(new MasterKey(TestKeys.KatKeyId, TestKeys.KatKey).KeyId.Span));
    }

    [Fact]
    public void File_key_is_hkdf_sha256_of_the_master_key_and_the_salt()
    {
        Assert.Equal(KatFileKeyHex, Convert.ToHexStringLower(EncryptedFileFormat.DeriveFileKey(TestKeys.KatKey, KatSalt)));
    }

    [Theory]
    [InlineData("hello", KatHelloFileHex)]
    [InlineData("", KatEmptyFileHex)]
    public async Task Writing_gives_the_known_file_bytes(string text, string expectedHex)
    {
        await WriteAsync("/f", System.Text.Encoding.ASCII.GetBytes(text));

        Assert.Equal(expectedHex, Convert.ToHexStringLower(File.ReadAllBytes(Path.Combine(_root, "f"))));
    }

    [Theory]
    [InlineData(65_536, 65_621, "467f2689005f9330e1865b6333314bc10a2ef4894b499ac0c7b9180349373003")] // one full chunk, then an empty one
    [InlineData(140_000, 140_101, "185406309a154619188f8fdf374715d92587c74023ef4551f457d904123c6599")] // two full chunks and a short one
    public async Task Writing_several_chunks_gives_the_known_file(int size, long expectedFileSize, string expectedSha256)
    {
        await WriteAsync("/f", Pattern(size));

        var bytes = File.ReadAllBytes(Path.Combine(_root, "f"));
        Assert.Equal(expectedFileSize, bytes.Length);
        Assert.Equal(expectedSha256, Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }

    [Theory]
    [InlineData("hello", KatHelloFileHex)]
    [InlineData("", KatEmptyFileHex)]
    public async Task Reading_the_known_file_bytes_gives_the_plaintext(string text, string fileHex)
    {
        File.WriteAllBytes(Path.Combine(_root, "f"), Convert.FromHexString(fileHex));

        Assert.Equal(text, System.Text.Encoding.ASCII.GetString(await ReadAsync("/f")));
        Assert.Equal(text.Length, (await CreateFileSystem().StatAsync("/f", true, Ct))!.Size);
    }

    [Theory]
    [InlineData(0, 69)]
    [InlineData(1, 70)]
    [InlineData(65_535, 65_604)]
    [InlineData(65_536, 65_621)]
    [InlineData(65_537, 65_622)]
    [InlineData(140_000, 140_101)]
    public void File_size_and_plaintext_size_convert_both_ways(long plaintext, long file)
    {
        Assert.Equal(file, EncryptedFileFormat.FileSize(plaintext));
        Assert.Equal(plaintext, EncryptedFileFormat.PlaintextSize(file));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(53)] // header only
    [InlineData(68)] // shorter than the empty last chunk
    [InlineData(53 + 65_552)] // cut after a full chunk
    [InlineData(53 + 65_552 + 15)]
    public void A_file_size_that_no_complete_file_has_gives_no_plaintext_size(long file)
    {
        Assert.Null(EncryptedFileFormat.PlaintextSize(file));
    }

    internal static byte[] Pattern(int size) => Enumerable.Range(0, size).Select(i => (byte)((i * 31 + 7) & 0xff)).ToArray();

    private EncryptedFileSystem CreateFileSystem()
        => new(new LocalFileSystem(_root), TestKeys.Provider(TestKeys.KatKeyId, (TestKeys.KatKeyId, TestKeys.KatKey)), salt => KatSalt.CopyTo(salt));

    private async Task WriteAsync(string path, byte[] content)
    {
        await using var handle = await CreateFileSystem().OpenAsync(path, FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate, null, Ct);
        // Odd write sizes, so the chunking does not depend on the write size.
        for (var offset = 0; offset < content.Length; offset += 10_007)
            await handle.WriteAsync(offset, content.AsMemory(offset, Math.Min(10_007, content.Length - offset)), Ct);
    }

    private async Task<byte[]> ReadAsync(string path)
    {
        await using var handle = await CreateFileSystem().OpenAsync(path, FileOpenFlags.Read, null, Ct);
        using var result = new MemoryStream();
        var buffer = new byte[32_768];
        int read;
        while ((read = await handle.ReadAsync(result.Length, buffer, Ct)) > 0)
            result.Write(buffer, 0, read);
        return result.ToArray();
    }
}
