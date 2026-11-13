namespace SshServer.Interfaces.Storage;

/// <summary>
/// The only exception that a storage backend (<see cref="IFileSystem"/>, <see cref="IFileHandle"/>) throws for a
/// failed operation. A backend catches the <c>System.IO</c> and SDK exceptions and translates them; the original
/// exception is the <see cref="Exception.InnerException"/>. The message has only virtual paths, never a physical
/// path or a storage URL. A canceled operation throws <see cref="OperationCanceledException"/> as usual.
/// </summary>
public sealed class FileSystemException : Exception
{
    public FileSystemException(FileSystemError error, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Error = error;
    }

    /// <summary>The reason of the failure.</summary>
    public FileSystemError Error { get; }
}
