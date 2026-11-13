using System.Diagnostics;

namespace FreeSftpSharp.Tests.Infrastructure;

/// <summary>
/// Creates symbolic links for the tests. On Linux and macOS every user can create them. On Windows a
/// symbolic link needs the "Create symbolic links" privilege (administrator or developer mode); without it,
/// a directory link falls back to a junction (no privilege needed), and a file link test is skipped.
/// </summary>
public static class FileLinks
{
    /// <summary>Creates a link to a directory. <paramref name="target"/> can be relative to the link's directory.</summary>
    public static void CreateDirectoryLink(string linkPath, string target)
    {
        try
        {
            Directory.CreateSymbolicLink(linkPath, target);
        }
        catch (Exception ex) when (OperatingSystem.IsWindows() && ex is IOException or UnauthorizedAccessException)
        {
            var absoluteTarget = Path.GetFullPath(target, Path.GetDirectoryName(linkPath)!);
            using var process = Process.Start(new ProcessStartInfo("cmd.exe")
            {
                ArgumentList = { "/c", "mklink", "/J", linkPath, absoluteTarget },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            })!;
            process.WaitForExit();
            if (process.ExitCode != 0 || !Directory.Exists(linkPath))
                throw new InvalidOperationException($"Cannot create a junction: {process.StandardError.ReadToEnd()}");
        }
    }

    /// <summary>Creates a link to a file (which does not have to exist). Skips the test on Windows without the privilege.</summary>
    public static void CreateFileLink(string linkPath, string target)
    {
        try
        {
            File.CreateSymbolicLink(linkPath, target);
        }
        catch (Exception ex) when (OperatingSystem.IsWindows() && ex is IOException or UnauthorizedAccessException)
        {
            Assert.Skip("Windows does not allow this user to create a symbolic link to a file.");
        }
    }
}
