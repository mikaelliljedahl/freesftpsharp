using System.Net;
using Google;
using Google.Apis.Auth.OAuth2.Responses;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.Gcs;

/// <summary>
/// Translates the exceptions of the Google client to <see cref="FileSystemException"/>: 404 is NoSuchFile, 401 and 403
/// are PermissionDenied, 412 (a failed "object must not exist" precondition) is AlreadyExists, everything else is
/// Failure with the status and the Google error reason in the message (the SFTP adapter logs it; the client never sees
/// the message). The original exception is the inner exception. The messages have only virtual paths, never the bucket
/// or the endpoint.
/// </summary>
internal static class GcsErrors
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

    /// <summary>True for a missing object or bucket (404).</summary>
    public static bool IsNotFound(GoogleApiException ex) => ex.HttpStatusCode == HttpStatusCode.NotFound;

    public static FileSystemException? Translate(Exception ex, string path, CancellationToken ct) => ex switch
    {
        FileSystemException own => own,
        OperationCanceledException when ct.IsCancellationRequested => null, // canceled by the caller: stays as it is
        GoogleApiException g => FromStatus(g.HttpStatusCode, Describe(g), path, ex),
        HttpRequestException { StatusCode: { } status } => FromStatus(status, $"HTTP {(int)status}", path, ex),
        TokenResponseException => new FileSystemException(FileSystemError.PermissionDenied, $"The storage refused the credentials: {path}", ex),
        HttpRequestException or IOException or OperationCanceledException
            => new FileSystemException(FileSystemError.Failure, $"The storage request failed ({ex.GetType().Name}): {path}", ex),
        _ => null,
    };

    private static FileSystemException FromStatus(HttpStatusCode status, string description, string path, Exception inner) => status switch
    {
        HttpStatusCode.NotFound => new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}", inner),
        HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized
            => new FileSystemException(FileSystemError.PermissionDenied, $"The storage refused access ({description}): {path}", inner),
        HttpStatusCode.PreconditionFailed => new FileSystemException(FileSystemError.AlreadyExists, $"Already exists: {path}", inner),
        _ => new FileSystemException(FileSystemError.Failure, $"The storage request failed ({description}): {path}", inner),
    };

    private static string Describe(GoogleApiException ex)
        => $"GCS {(int)ex.HttpStatusCode} {ex.Error?.Errors?.FirstOrDefault()?.Reason}".TrimEnd();
}
