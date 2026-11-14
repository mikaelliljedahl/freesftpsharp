using System.Net;
using Amazon.Runtime;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.S3;

/// <summary>
/// Translates the exceptions of the AWS SDK to <see cref="FileSystemException"/>: 404 is NoSuchFile, 403 is
/// PermissionDenied, everything else is Failure with the status, the S3 error code and the request id in the message
/// (the SFTP adapter logs it; the client never sees the message). The original exception is the inner exception. The
/// messages have only virtual paths, never the bucket or the endpoint.
/// </summary>
internal static class S3Errors
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

    /// <summary>True for a missing object (404), not for a missing bucket.</summary>
    public static bool IsNotFound(AmazonServiceException ex)
        => ex.StatusCode == HttpStatusCode.NotFound && ex.ErrorCode != "NoSuchBucket";

    public static FileSystemException? Translate(Exception ex, string path, CancellationToken ct) => ex switch
    {
        FileSystemException own => own,
        OperationCanceledException when ct.IsCancellationRequested => null, // canceled by the caller: stays as it is
        AmazonServiceException s when IsNotFound(s) => new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}", ex),
        AmazonServiceException { StatusCode: HttpStatusCode.Forbidden } s
            => new FileSystemException(FileSystemError.PermissionDenied, $"The storage refused access ({Describe(s)}): {path}", ex),
        AmazonServiceException { StatusCode: HttpStatusCode.PreconditionFailed } s
            => new FileSystemException(FileSystemError.Failure, $"The file was changed by another writer while it was open ({Describe(s)}): {path}", ex),
        AmazonServiceException s => new FileSystemException(FileSystemError.Failure, $"The storage request failed ({Describe(s)}): {path}", ex),
        AmazonClientException or HttpRequestException or IOException or OperationCanceledException
            => new FileSystemException(FileSystemError.Failure, $"The storage request failed ({ex.GetType().Name}): {path}", ex),
        _ => null,
    };

    private static string Describe(AmazonServiceException ex)
        => $"S3 {(int)ex.StatusCode} {ex.ErrorCode}, request id {ex.RequestId}";
}
