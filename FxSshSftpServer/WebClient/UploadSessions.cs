using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Storage;

namespace FxSshSftpServer.WebClient
{
    /// <summary>Why a chunk was refused by <see cref="UploadSessions"/>; the endpoint maps it to a status code.</summary>
    public sealed class UploadException : Exception
    {
        public UploadException(int statusCode, string message, long? offset = null) : base(message)
        {
            StatusCode = statusCode;
            Offset = offset;
        }

        public int StatusCode { get; }

        /// <summary>The bytes the server has of the upload, so the browser can continue there.</summary>
        public long? Offset { get; }
    }

    /// <summary>The state of an upload after a chunk.</summary>
    /// <param name="Offset">The bytes written so far.</param>
    /// <param name="Complete">True when the last chunk was written and the file is closed.</param>
    public readonly record struct UploadProgress(long Offset, bool Complete);

    /// <summary>
    /// The chunked uploads of the web client (#69). The first chunk of a file opens it through the storage decorator
    /// chain of the session (permissions, quotas, events, connection tracking); every chunk is written at once with
    /// <see cref="IFileHandle.WriteAsync"/> in small blocks, so a file is never held in memory or in a temporary file. The
    /// handle stays open between the chunks; the last chunk closes it (the upload event). The chunks come in order (a
    /// storage without random access writes only at the end): a chunk that does not start at the bytes written so far is
    /// refused with the right offset, so an interrupted upload continues there (<see cref="GetOffset"/>). An upload
    /// without a chunk for <see cref="WebClientOptions.UploadIdleMinutes"/>, or of a session that ended, is aborted
    /// (<see cref="IFileHandle.AbortAsync"/>).
    /// </summary>
    public sealed partial class UploadSessions
    {
        private const int BlockSize = 256 * 1024;

        private sealed class Upload
        {
            public required Guid Session { get; init; }
            public required string Path { get; init; }
            public required long Total { get; init; }
            public required IFileHandle Handle { get; init; }
            public readonly SemaphoreSlim Lock = new(1, 1);
            public long Offset;
            public long LastTicks;
            public bool Closed;
        }

        private readonly ConcurrentDictionary<(Guid Session, string Id), Upload> _uploads = new();
        private readonly TimeProvider _time;
        private readonly WebClientOptions _options;
        private readonly ILogger<UploadSessions> _logger;

        public UploadSessions(TimeProvider time, IOptions<WebClientOptions> options, ILogger<UploadSessions> logger)
        {
            _time = time;
            _options = options.Value;
            _logger = logger;
        }

        /// <summary>True for an upload id that the browser may choose: 8 to 64 letters, digits, '-' or '_'.</summary>
        public static bool IsValidId(string id) => id != null && UploadIdRegex().IsMatch(id);

        /// <summary>The bytes the server has of an unfinished upload, or null when there is none (start again at 0).</summary>
        public long? GetOffset(Guid session, string id, string path)
        {
            if (!_uploads.TryGetValue((session, id), out var upload) || !SamePath(upload.Path, path))
                return null;
            return Interlocked.Read(ref upload.Offset);
        }

        /// <summary>
        /// Writes one chunk. A chunk at offset 0 of an unknown id opens the file with <paramref name="openAsync"/> (it
        /// creates the file through the decorator chain). Throws <see cref="UploadException"/> for a chunk out of order or
        /// with a wrong length, and <see cref="FileSystemException"/> from the storage (permission, quota); after a storage
        /// error the upload is aborted.
        /// </summary>
        public async Task<UploadProgress> WriteChunkAsync(Guid session, string id, string path, ContentRange range, Stream body,
            Func<CancellationToken, ValueTask<IFileHandle>> openAsync, CancellationToken ct)
        {
            var key = (session, id);
            if (!_uploads.TryGetValue(key, out var upload))
            {
                if (range.First != 0)
                    throw new UploadException(409, "The upload is not known (any more). Start it again.", 0);
                if (_uploads.Keys.Count(k => k.Session == session) >= _options.MaxUploadsPerSession)
                    throw new UploadException(429, $"At most {_options.MaxUploadsPerSession} uploads at the same time.");
                var handle = await openAsync(ct);
                upload = new Upload { Session = session, Path = path, Total = range.Total, Handle = handle, LastTicks = _time.GetUtcNow().UtcTicks };
                if (!_uploads.TryAdd(key, upload))
                {
                    await handle.AbortAsync();
                    throw new UploadException(409, "The upload was started twice at the same time.");
                }
            }

            await upload.Lock.WaitAsync(ct);
            try
            {
                if (upload.Closed)
                    throw new UploadException(409, "The upload is not known (any more). Start it again.", 0);
                if (!SamePath(upload.Path, path) || upload.Total != range.Total)
                    throw new UploadException(409, "The chunk belongs to another file.");
                if (range.First != upload.Offset)
                    throw new UploadException(409, "The chunk is not the next part of the file.", upload.Offset);

                try
                {
                    var written = await CopyAsync(body, upload, range.Length, ct);
                    upload.LastTicks = _time.GetUtcNow().UtcTicks;
                    if (written != range.Length)
                        throw new UploadException(400, $"The chunk has {written} bytes instead of {range.Length}.", upload.Offset);
                    if (upload.Offset < upload.Total)
                        return new UploadProgress(upload.Offset, false);

                    // The last chunk: closing the file completes it (an object store publishes it now; the upload event).
                    upload.Closed = true;
                    _uploads.TryRemove(key, out _);
                    await upload.Handle.DisposeAsync();
                    return new UploadProgress(upload.Offset, true);
                }
                catch (FileSystemException)
                {
                    await AbortLockedAsync(key, upload);
                    throw;
                }
            }
            finally
            {
                upload.Lock.Release();
            }
        }

        /// <summary>Aborts an unfinished upload (the browser canceled it). False when there is none.</summary>
        public async Task<bool> AbortAsync(Guid session, string id)
        {
            if (!_uploads.TryGetValue((session, id), out var upload))
                return false;
            await upload.Lock.WaitAsync();
            try
            {
                await AbortLockedAsync((session, id), upload);
            }
            finally
            {
                upload.Lock.Release();
            }
            return true;
        }

        /// <summary>Aborts the unfinished uploads of a session that ended.</summary>
        public async Task AbortSessionAsync(Guid session)
        {
            foreach (var key in _uploads.Keys.Where(k => k.Session == session).ToList())
                await AbortAsync(key.Session, key.Id);
        }

        /// <summary>Aborts the uploads without a chunk for <see cref="WebClientOptions.UploadIdleMinutes"/>. Returns how many.</summary>
        public async Task<int> SweepAsync()
        {
            var limit = _time.GetUtcNow().UtcTicks - _options.UploadIdle.Ticks;
            var aborted = 0;
            foreach (var (key, upload) in _uploads)
            {
                if (Interlocked.Read(ref upload.LastTicks) >= limit || !upload.Lock.Wait(0))
                    continue; // active, or a chunk is being written now
                try
                {
                    _logger.LogInformation("The unfinished upload of {Path} was aborted after {Minutes} minutes without a chunk.",
                        upload.Path, _options.UploadIdleMinutes);
                    await AbortLockedAsync(key, upload);
                    aborted++;
                }
                finally
                {
                    upload.Lock.Release();
                }
            }
            return aborted;
        }

        /// <summary>The number of unfinished uploads (for the tests and the log).</summary>
        public int Count => _uploads.Count;

        private async Task<long> CopyAsync(Stream body, Upload upload, long length, CancellationToken ct)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(BlockSize);
            try
            {
                long written = 0;
                while (written < length)
                {
                    var read = await body.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, length - written)), ct);
                    if (read == 0)
                        break;
                    await upload.Handle.WriteAsync(upload.Offset, buffer.AsMemory(0, read), ct);
                    upload.Offset += read;
                    written += read;
                }
                // A body longer than the range is refused: one more byte tells it.
                if (written == length && await body.ReadAsync(buffer.AsMemory(0, 1), ct) > 0)
                    return written + 1;
                return written;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private async Task AbortLockedAsync((Guid, string) key, Upload upload)
        {
            _uploads.TryRemove(key, out _);
            if (upload.Closed)
                return;
            upload.Closed = true;
            try
            {
                await upload.Handle.AbortAsync();
            }
            catch (Exception ex) when (ex is FileSystemException or IOException)
            {
                _logger.LogWarning(ex, "The unfinished upload of {Path} could not be aborted cleanly.", upload.Path);
            }
        }

        private static bool SamePath(string a, string b) => string.Equals(VirtualPath.Normalize(a), VirtualPath.Normalize(b), StringComparison.Ordinal);

        [GeneratedRegex("^[A-Za-z0-9_-]{8,64}$")]
        private static partial Regex UploadIdRegex();
    }
}
