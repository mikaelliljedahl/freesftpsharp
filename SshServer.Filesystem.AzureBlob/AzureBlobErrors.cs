using Azure;
using Azure.Identity;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.AzureBlob;

/// <summary>
/// Translates the exceptions of the Azure SDK to <see cref="FileSystemException"/>: 404 is NoSuchFile, 403 (and 401) is
/// PermissionDenied, 409 BlobAlreadyExists is AlreadyExists, everything else is Failure with the status, the Azure error
/// code and the request id in the message (the SFTP adapter logs it; the client never sees the message). The original
/// exception is the inner exception. The messages have only virtual paths, never the account or the container.
/// </summary>
internal static class AzureBlobErrors
{
    public static async Task<T> RunAsync<T>(string path, Func<Task<T>> operation, CancellationToken ct)
    {
        try
        {
            return await operation().ConfigureAwait(false);
        }
        catch (Exception ex) when (Translate(ex, path, ct) is { } translated)
        {
            throw translated;
        }
    }

    public static Task RunAsync(string path, Func<Task> operation, CancellationToken ct)
        => RunAsync(path, async () => { await operation().ConfigureAwait(false); return true; }, ct);

    /// <summary>True for a missing blob (404), not for a missing container.</summary>
    public static bool IsNotFound(RequestFailedException ex)
        => ex.Status == 404 && ex.ErrorCode is not ("ContainerNotFound" or "AccountNotFound");

    public static FileSystemException? Translate(Exception ex, string path, CancellationToken ct) => ex switch
    {
        FileSystemException own => own,
        OperationCanceledException when ct.IsCancellationRequested => null, // canceled by the caller: stays as it is
        RequestFailedException r when IsNotFound(r) => new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}", ex),
        RequestFailedException { Status: 409, ErrorCode: "BlobAlreadyExists" }
            => new FileSystemException(FileSystemError.AlreadyExists, $"Already exists: {path}", ex),
        RequestFailedException { Status: 403 or 401 } r
            => new FileSystemException(FileSystemError.PermissionDenied, $"The storage refused access ({Describe(r)}): {path}", ex),
        RequestFailedException { Status: 412 } r
            => new FileSystemException(FileSystemError.Failure, $"The file was changed by another writer while it was open ({Describe(r)}): {path}", ex),
        RequestFailedException r => new FileSystemException(FileSystemError.Failure, $"The storage request failed ({Describe(r)}): {path}", ex),
        AuthenticationFailedException or HttpRequestException or IOException or AggregateException or OperationCanceledException
            => new FileSystemException(FileSystemError.Failure, $"The storage request failed ({ex.GetType().Name}): {path}", ex),
        _ => null,
    };

    private static string Describe(RequestFailedException ex)
        => $"Azure {ex.Status} {ex.ErrorCode}, request id {RequestId(ex)}";

    private static string RequestId(RequestFailedException ex)
        => ex.GetRawResponse()?.Headers.TryGetValue("x-ms-request-id", out var id) == true ? id : "unknown";
}
