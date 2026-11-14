#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Storage
{
    /// <summary>A registered storage provider for the admin UI.</summary>
    public sealed record StorageProviderInfo(string Name, string DisplayName, string? Description, IReadOnlyList<StorageOptionField> Fields);

    /// <summary>
    /// The editable form of one storage configuration: the provider and the text of each option field. A secret is
    /// never filled in: <see cref="StoredSecrets"/> tells which secrets have a stored value, an empty field keeps it, and
    /// <see cref="ClearSecrets"/> removes it.
    /// </summary>
    public sealed class StorageSettings
    {
        /// <summary>The provider name.</summary>
        public string Provider { get; set; } = string.Empty;

        /// <summary>The text of each field by <see cref="StorageOptionField.Name"/>; "true" or "false" for a check box.</summary>
        public Dictionary<string, string> Values { get; } = new(StringComparer.Ordinal);

        /// <summary>The secrets with a stored value.</summary>
        public HashSet<string> StoredSecrets { get; } = new(StringComparer.Ordinal);

        /// <summary>The stored secrets to remove at the next save.</summary>
        public HashSet<string> ClearSecrets { get; } = new(StringComparer.Ordinal);

        /// <summary>Why the stored configuration could not be read (for example an unknown provider); null when it could.</summary>
        public string? LoadProblem { get; internal set; }

        /// <summary>The stored configuration that this form edits, or null for a new one.</summary>
        internal StorageConfig? Stored { get; init; }

        public string Value(string field) => Values.TryGetValue(field, out var value) ? value : string.Empty;
    }

    /// <summary>The result of <see cref="StorageConfigService.Build"/>: the configuration to store, or the problems.</summary>
    public sealed record StorageBuildResult(StorageConfig? Config, IReadOnlyList<string> Problems)
    {
        public bool IsValid => Config != null;
    }

    /// <summary>The result of <see cref="StorageConfigService.TestAsync"/>.</summary>
    public sealed record StorageTestResult(bool Success, string Message);

    /// <summary>
    /// The application service for storage configurations (issue #56), used by the admin UI (user storage and virtual
    /// folders) and later the REST API (#67): the registered providers and their option fields, the form of a stored
    /// configuration without its secrets, the validated configuration to store (by the provider), and a connection test.
    /// It never switches on a provider name.
    /// </summary>
    public sealed class StorageConfigService
    {
        /// <summary>The time a connection test may take.</summary>
        public static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(20);

        private const int TestListLimit = 1000;

        private readonly IStorageProviderRegistry _registry;
        private readonly StorageOptionsCodec _codec;

        public StorageConfigService(IStorageProviderRegistry registry, StorageOptionsCodec codec)
        {
            _registry = registry;
            _codec = codec;
        }

        /// <summary>The registered providers, by display name.</summary>
        public IReadOnlyList<StorageProviderInfo> Providers => _registry.Providers
            .Select(Describe)
            .OrderBy(p => p.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        /// <summary>The provider with this name, or null when none is registered.</summary>
        public StorageProviderInfo? Find(string? provider)
            => _registry.Providers.FirstOrDefault(p => string.Equals(p.Name, provider, StringComparison.OrdinalIgnoreCase)) is { } found ? Describe(found) : null;

        /// <summary>The display name of the provider of a stored configuration, or its name when it is not registered.</summary>
        public string DisplayName(StorageConfig config) => Find(config.Provider)?.DisplayName ?? config.Provider;

        /// <summary>The form of a stored configuration, without secrets; an empty form (no provider) for null.</summary>
        public StorageSettings Edit(StorageConfig? stored)
        {
            if (stored is null)
                return new StorageSettings();

            var settings = new StorageSettings { Provider = stored.Provider, Stored = stored };
            try
            {
                var provider = _codec.ProviderOf(stored);
                settings.Provider = provider.Name;
                Fill(settings, _codec.Decode(stored), provider);
            }
            catch (ArgumentException ex)
            {
                settings.LoadProblem = ex.Message;
            }
            return settings;
        }

        /// <summary>
        /// Selects another provider in the form: the fields get the stored values when it is the stored provider, and the
        /// defaults of the options type otherwise.
        /// </summary>
        public void SelectProvider(StorageSettings settings, string provider)
        {
            settings.Provider = provider ?? string.Empty;
            settings.Values.Clear();
            settings.StoredSecrets.Clear();
            settings.ClearSecrets.Clear();
            settings.LoadProblem = null;
            var info = _registry.Providers.FirstOrDefault(p => string.Equals(p.Name, provider, StringComparison.OrdinalIgnoreCase));
            if (info is null)
                return;
            settings.Provider = info.Name;
            try
            {
                var options = IsStoredProvider(settings, info)
                    ? _codec.Decode(settings.Stored!)
                    : StorageOptionsCodec.FromNode(info, new JsonObject());
                Fill(settings, options, info);
            }
            catch (ArgumentException ex)
            {
                settings.LoadProblem = ex.Message;
            }
        }

        /// <summary>
        /// The configuration to store from the form, with the secrets encrypted, or the problems (from the fields and from
        /// the validation of the provider).
        /// </summary>
        public StorageBuildResult Build(StorageSettings settings)
        {
            var (provider, options, problems) = BuildOptions(settings);
            if (problems.Count > 0)
                return new StorageBuildResult(null, problems);
            return new StorageBuildResult(_codec.Encode(provider!.Name, options!), []);
        }

        /// <summary>
        /// Creates the storage from the form (not saved) and lists its root, so the admin sees whether the settings work.
        /// </summary>
        public async Task<StorageTestResult> TestAsync(StorageSettings settings, CancellationToken ct)
        {
            var (provider, options, problems) = BuildOptions(settings);
            if (problems.Count > 0)
                return new StorageTestResult(false, string.Join(" ", problems));

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TestTimeout);
            try
            {
                var fileSystem = await provider!.CreateAsync(options!, timeout.Token);
                var count = 0;
                await foreach (var _ in fileSystem.ListAsync(VirtualPath.Root, timeout.Token))
                {
                    if (++count >= TestListLimit)
                        break;
                }
                var entries = count switch
                {
                    0 => "it is empty",
                    1 => "it has 1 entry",
                    >= TestListLimit => $"it has {TestListLimit} or more entries",
                    _ => $"it has {count} entries",
                };
                return new StorageTestResult(true, $"The storage works: the root was listed, and {entries}.");
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return new StorageTestResult(false, $"The storage did not answer within {TestTimeout.TotalSeconds:0} seconds.");
            }
            catch (Exception ex) when (ex is FileSystemException or ArgumentException or InvalidOperationException)
            {
                return new StorageTestResult(false, $"The storage does not work: {ex.Message}");
            }
        }

        /// <summary>
        /// Every option of a stored configuration as plain JSON, for an export (the REST API dump, #67): also the options
        /// that the form does not show. Each secret is decrypted and given to <paramref name="exportSecret"/> (option name,
        /// plain text), which returns the value to export (for example encrypted with a passphrase), or null to leave it out.
        /// Throws <see cref="ArgumentException"/> when the provider is not registered or a secret cannot be decrypted.
        /// </summary>
        public JsonObject Export(StorageConfig stored, Func<string, string, string?> exportSecret)
        {
            var provider = _codec.ProviderOf(stored);
            var node = _codec.DecodeNode(provider, stored);
            foreach (var field in StorageOptionField.Of(provider.OptionsType).Where(f => f.IsSecret))
            {
                if (node[field.Name] is not JsonValue value || !value.TryGetValue<string>(out var text) || text.Length == 0)
                    continue;
                var exported = exportSecret(field.Name, text);
                if (exported is null)
                    node.Remove(field.Name);
                else
                    node[field.Name] = exported;
            }
            return node;
        }

        /// <summary>
        /// The configuration to store from the plain JSON options of an export (<see cref="Export"/>): each secret is
        /// given to <paramref name="importSecret"/> for its plain text, and is encrypted again with the keys of this
        /// server. The provider validates the options.
        /// </summary>
        public StorageBuildResult Import(string provider, JsonObject options, Func<string, string> importSecret)
        {
            var storageProvider = _registry.Providers.FirstOrDefault(p => string.Equals(p.Name, provider, StringComparison.OrdinalIgnoreCase));
            if (storageProvider is null)
                return new StorageBuildResult(null, [$"The storage provider '{provider}' is not registered."]);

            var node = (JsonObject)options.DeepClone();
            object parsed;
            try
            {
                foreach (var field in StorageOptionField.Of(storageProvider.OptionsType).Where(f => f.IsSecret))
                {
                    var key = node.Select(p => p.Key).FirstOrDefault(k => string.Equals(k, field.Name, StringComparison.OrdinalIgnoreCase));
                    if (key != null && node[key] is JsonValue value && value.TryGetValue<string>(out var text) && text.Length > 0)
                        node[key] = importSecret(text);
                }
                parsed = StorageOptionsCodec.FromNode(storageProvider, node);
            }
            catch (ArgumentException ex)
            {
                return new StorageBuildResult(null, [ex.Message]);
            }

            var problems = storageProvider.Validate(parsed).ToList();
            return problems.Count > 0
                ? new StorageBuildResult(null, problems)
                : new StorageBuildResult(_codec.Encode(storageProvider.Name, parsed), []);
        }

        private (IStorageProvider? Provider, object? Options, List<string> Problems) BuildOptions(StorageSettings settings)
        {
            var problems = new List<string>();
            var provider = _registry.Providers.FirstOrDefault(p => string.Equals(p.Name, settings.Provider, StringComparison.OrdinalIgnoreCase));
            if (provider is null)
            {
                problems.Add(string.IsNullOrWhiteSpace(settings.Provider)
                    ? "Select a storage provider."
                    : $"The storage provider '{settings.Provider}' is not registered.");
                return (null, null, problems);
            }

            // Start from the stored options: fields that the form does not show keep their value, and so do the secrets.
            JsonObject node;
            try
            {
                node = IsStoredProvider(settings, provider) ? _codec.DecodeNode(provider, settings.Stored!) : new JsonObject();
            }
            catch (ArgumentException)
            {
                // The stored options cannot be read (for example a lost key): only the form counts, and a secret must be entered again.
                node = new JsonObject();
            }

            foreach (var field in StorageOptionField.Of(provider.OptionsType))
            {
                var text = settings.Value(field.Name);
                switch (field.Kind)
                {
                    case StorageOptionKind.Text when field.IsSecret:
                        if (text.Length > 0)
                            node[field.Name] = text;
                        else if (settings.ClearSecrets.Contains(field.Name) || !settings.StoredSecrets.Contains(field.Name))
                            node.Remove(field.Name);
                        break;
                    case StorageOptionKind.Text:
                    case StorageOptionKind.Choice:
                        text = text.Trim();
                        if (text.Length == 0)
                            node.Remove(field.Name);
                        else
                            node[field.Name] = text;
                        break;
                    case StorageOptionKind.Number:
                        text = text.Trim();
                        if (text.Length == 0)
                            node.Remove(field.Name);
                        else if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number))
                            node[field.Name] = number;
                        else
                            problems.Add($"{field.Label} must be a whole number.");
                        break;
                    case StorageOptionKind.Boolean:
                        node[field.Name] = string.Equals(text, "true", StringComparison.OrdinalIgnoreCase);
                        break;
                }
            }
            if (problems.Count > 0)
                return (provider, null, problems);

            object options;
            try
            {
                options = StorageOptionsCodec.FromNode(provider, node);
            }
            catch (ArgumentException ex)
            {
                problems.Add(ex.Message);
                return (provider, null, problems);
            }
            problems.AddRange(provider.Validate(options));
            return (provider, options, problems);
        }

        private static bool IsStoredProvider(StorageSettings settings, IStorageProvider provider)
            => settings.Stored is { } stored && string.Equals(stored.Provider, provider.Name, StringComparison.OrdinalIgnoreCase);

        private static void Fill(StorageSettings settings, object options, IStorageProvider provider)
        {
            var node = StorageOptionsCodec.ToNode(options, provider.OptionsType);
            foreach (var field in StorageOptionField.Of(provider.OptionsType))
            {
                var value = node[field.Name];
                var text = value is JsonValue v
                    ? v.TryGetValue<string>(out var s) ? s : v.TryGetValue<bool>(out var b) ? (b ? "true" : "false") : v.ToJsonString()
                    : string.Empty;
                if (field.IsSecret)
                {
                    if (text.Length > 0)
                        settings.StoredSecrets.Add(field.Name);
                    continue; // a secret is never shown
                }
                settings.Values[field.Name] = field.Kind == StorageOptionKind.Boolean && text.Length == 0 ? "false" : text;
            }
        }

        private static StorageProviderInfo Describe(IStorageProvider provider)
            => new(provider.Name, StorageOptionField.DisplayNameOf(provider.OptionsType, provider.Name),
                StorageOptionField.DescriptionOf(provider.OptionsType), StorageOptionField.Of(provider.OptionsType));
    }
}
