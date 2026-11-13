namespace FreeSftpSharp.Tests.Settings;

/// <summary>A new empty directory under the system temp directory, deleted on dispose.</summary>
internal sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "freesftpsharp-settings-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string File(string name) => System.IO.Path.Combine(Path, name);

    /// <summary>A SQLite connection string for a file in this directory. No pooling, so the file can be deleted.</summary>
    public string SqliteConnectionString(string name = "freesftpsharp.db") => $"Data Source={File(name)};Pooling=False";

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
