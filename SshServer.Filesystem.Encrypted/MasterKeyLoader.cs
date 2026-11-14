using System.Security.Cryptography;

namespace SshServer.Filesystem.Encrypted;

/// <summary>
/// Reads the master keys of <see cref="EncryptedStorageOptions"/> (inline base64 or key files) and reports every
/// problem. The messages name the key id and the problem, never the key.
/// </summary>
internal static class MasterKeyLoader
{
    public sealed record Result(IReadOnlyList<MasterKey> Keys, MasterKey? ActiveKey, IReadOnlyList<string> Problems);

    public static Result Load(EncryptedStorageOptions options)
    {
        var problems = new List<string>();
        var keys = new List<MasterKey>();
        var ids = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i < options.Keys.Count; i++)
        {
            var entry = options.Keys[i];
            var id = entry.Id?.Trim();
            if (string.IsNullOrEmpty(id))
            {
                problems.Add($"{EncryptedStorageOptions.SectionName}:Keys:{i} has no Id.");
                continue;
            }
            if (!ids.Add(id))
            {
                problems.Add($"The key id '{id}' is used twice.");
                continue;
            }

            var bytes = ReadKey(entry, id, problems);
            if (bytes == null)
                continue;
            try
            {
                if (bytes.Length != EncryptedFileFormat.MasterKeySize)
                    problems.Add($"The key '{id}' must be {EncryptedFileFormat.MasterKeySize} bytes (base64 of 32 random bytes), not {bytes.Length} bytes.");
                else
                    keys.Add(new MasterKey(id, bytes));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }

        MasterKey? active = null;
        var activeId = options.ActiveKeyId?.Trim();
        if (string.IsNullOrEmpty(activeId))
            problems.Add($"{EncryptedStorageOptions.SectionName}:ActiveKeyId is not set.");
        else if ((active = keys.FirstOrDefault(k => k.Id == activeId)) == null && !ids.Contains(activeId))
            problems.Add($"The active key '{activeId}' is not in {EncryptedStorageOptions.SectionName}:Keys.");

        return new Result(keys, active, problems);
    }

    private static byte[]? ReadKey(EncryptionKeyOptions entry, string id, List<string> problems)
    {
        var hasKey = !string.IsNullOrWhiteSpace(entry.Key);
        var hasFile = !string.IsNullOrWhiteSpace(entry.KeyFile);
        if (hasKey == hasFile)
        {
            problems.Add($"The key '{id}' needs exactly one of Key or KeyFile.");
            return null;
        }

        string text;
        if (hasKey)
        {
            text = entry.Key!;
        }
        else
        {
            var path = Path.GetFullPath(entry.KeyFile!);
            if (!File.Exists(path))
            {
                problems.Add($"The key file of the key '{id}' does not exist: {path}");
                return null;
            }
            if (!OperatingSystem.IsWindows()
                && (File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
                    | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
            {
                problems.Add($"The key file of the key '{id}' can be read by other users; allow only the owner (chmod 600): {path}");
                return null;
            }
            try
            {
                text = File.ReadAllText(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                problems.Add($"The key file of the key '{id}' cannot be read: {path} ({ex.GetType().Name})");
                return null;
            }
        }

        try
        {
            return Convert.FromBase64String(text.Trim());
        }
        catch (FormatException)
        {
            problems.Add($"The key '{id}' is not valid base64.");
            return null;
        }
    }
}
