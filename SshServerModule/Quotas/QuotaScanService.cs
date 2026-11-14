#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace SshServerModule.Quotas
{
    /// <summary>
    /// Recomputes the disk usage of a quota scope from its storage (issue #62): it lists the storage recursively and sets
    /// the counters of the <see cref="QuotaUsageTracker"/> to the size and number of the files. The own storage of a user
    /// is listed without the paths where virtual folders are mounted (the user cannot reach them). A scan is requested by
    /// the admin UI, by the first session of a scope that was never scanned, and every
    /// <see cref="QuotaOptions.ScanIntervalHours"/> for every scope with a quota; the requests run one after the other on
    /// the background task of this service (<see cref="QuotaScanQueue"/>), so a scope is never scanned twice at the same time.
    /// <para>
    /// The counters are approximate: a file that is uploaded while the scan runs can be missed or counted. The next scan
    /// corrects it.
    /// </para>
    /// </summary>
    public sealed class QuotaScanService : BackgroundService
    {
        private readonly ISettingsRepository? _repository;
        private readonly IUserStorageResolver _resolver;
        private readonly IStorageProviderRegistry _registry;
        private readonly StorageOptionsCodec _codec;
        private readonly IEffectiveQuotaService _quotas;
        private readonly QuotaUsageTracker _tracker;
        private readonly QuotaOptions _options;
        private readonly TimeProvider _time;
        private readonly ILogger _logger;
        private readonly QuotaScanQueue _queue;

        public QuotaScanService(IUserStorageResolver resolver, IStorageProviderRegistry registry, StorageOptionsCodec codec,
            IEffectiveQuotaService quotas, QuotaUsageTracker tracker, QuotaScanQueue queue, ISettingsRepository? repository = null,
            IOptions<QuotaOptions>? options = null, TimeProvider? time = null, ILogger<QuotaScanService>? logger = null)
        {
            _queue = queue;
            _repository = repository;
            _resolver = resolver;
            _registry = registry;
            _codec = codec;
            _quotas = quotas;
            _tracker = tracker;
            _options = options?.Value ?? new QuotaOptions();
            _time = time ?? TimeProvider.System;
            _logger = (ILogger?)logger ?? NullLogger.Instance;
        }

        /// <summary>Queues a scan of every scope that has a disk quota (the scheduled scan). Returns the number of queued scopes.</summary>
        public int RequestAllWithQuota()
        {
            var count = 0;
            foreach (var scope in (_repository?.GetAllUsers() ?? []).SelectMany(ScopesWithQuota).Distinct())
            {
                if (_queue.Request(scope))
                    count++;
            }
            return count;
        }

        /// <summary>The scopes of a user that have a disk quota: its own storage and the folders mounted with a quota.</summary>
        public IReadOnlyList<QuotaScope> ScopesWithQuota(User user)
        {
            var quotas = _quotas.Resolve(user);
            var scopes = new List<QuotaScope>();
            if (quotas.Disk is not null)
                scopes.Add(QuotaScope.ForUser(user.Username));
            foreach (var mount in user.VirtualFolders ?? [])
            {
                if (quotas.ForMount(mount.MountPath) is not null)
                    scopes.Add(QuotaScope.ForFolder(mount.VirtualFolderId));
            }
            return scopes;
        }

        /// <summary>Scans the scope now and sets its counters. Null when the user or the folder does not exist (any more).</summary>
        public async Task<QuotaUsage?> ScanAsync(QuotaScope scope, CancellationToken ct)
        {
            IFileSystem fileSystem;
            var skip = new HashSet<string>(StringComparer.Ordinal);
            if (scope.Kind == QuotaScopeKind.User)
            {
                var user = _repository?.GetUser(scope.Key);
                if (user is null)
                    return null;
                var storage = _resolver.Resolve(user);
                fileSystem = await CreateAsync(storage.Root, ct);
                foreach (var mount in storage.Mounts)
                    skip.Add(mount.Path);
                if ((fileSystem.Capabilities & StorageCapabilities.CaseInsensitivePaths) != 0)
                    skip = new HashSet<string>(skip, StringComparer.OrdinalIgnoreCase);
            }
            else
            {
                var folder = int.TryParse(scope.Key, out var id) ? _repository?.GetVirtualFolder(id) : null;
                if (folder is null)
                    return null;
                fileSystem = await CreateAsync(folder.Storage, ct);
            }

            var started = _time.GetTimestamp();
            var (bytes, files) = await CountAsync(fileSystem, VirtualPath.Root, skip, ct);
            var usage = await _tracker.SetDiskUsageAsync(scope, bytes, files, ct);
            _logger.LogInformation("Scanned the quota usage of {Scope}: {Bytes} bytes in {Files} files ({Seconds:F1} s).",
                scope, bytes, files, _time.GetElapsedTime(started).TotalSeconds);
            return usage;
        }

        private async ValueTask<IFileSystem> CreateAsync(StorageConfig config, CancellationToken ct)
            => await _registry.Get(config.Provider).CreateAsync(_codec.Decode(config), ct);

        private static async Task<(long Bytes, long Files)> CountAsync(IFileSystem fileSystem, string root, HashSet<string> skip, CancellationToken ct)
        {
            long bytes = 0, files = 0;
            var directories = new Stack<string>();
            directories.Push(root);
            while (directories.Count > 0)
            {
                var directory = directories.Pop();
                try
                {
                    await foreach (var entry in fileSystem.ListAsync(directory, ct))
                    {
                        var path = VirtualPath.Combine(directory, entry.Name);
                        if (entry.Type == FileSystemEntryType.File)
                        {
                            bytes += entry.Size;
                            files++;
                        }
                        else if (entry.IsDirectory && !skip.Contains(path))
                        {
                            directories.Push(path);
                        }
                    }
                }
                catch (FileSystemException ex) when (ex.Error is FileSystemError.NoSuchFile or FileSystemError.NotADirectory && directory != root)
                {
                    // Removed while the scan ran.
                }
            }
            return (bytes, files);
        }

        /// <summary>Runs one queued request: the scope, or every scope with a quota of the user.</summary>
        public async Task RunAsync(QuotaScanRequest request, CancellationToken ct)
        {
            if (request.Scope is { } scope)
            {
                await ScanAsync(scope, ct);
                return;
            }
            if (request.Username is { } username && _repository?.GetUser(username) is { } user)
            {
                foreach (var userScope in ScopesWithQuota(user))
                    await ScanAsync(userScope, ct);
            }
        }

        /// <summary>Runs the queued requests now, until the queue is empty (the background task does this too).</summary>
        public async Task RunPendingAsync(CancellationToken ct)
        {
            while (_queue.TryRead(out var request))
                await RunAsync(request, ct);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var schedule = ScheduleAsync(stoppingToken);
            try
            {
                await foreach (var request in _queue.ReadAllAsync(stoppingToken))
                {
                    try
                    {
                        await RunAsync(request, stoppingToken);
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "The quota scan of {Request} failed; the counters were not changed.", (object?)request.Scope ?? request.Username);
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
            }
            await schedule;
        }

        private async Task ScheduleAsync(CancellationToken ct)
        {
            if (_options.ScanIntervalHours <= 0)
                return;
            var interval = TimeSpan.FromHours(_options.ScanIntervalHours);
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(interval, _time, ct);
                    var count = RequestAllWithQuota();
                    _logger.LogInformation("The scheduled quota scan queued {Count} scope(s).", count);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "The scheduled quota scan could not read the users; it runs again in {Interval}.", interval);
                }
            }
        }
    }
}
