#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Storage
{
    /// <summary>The providers registered with <c>AddXStorage()</c>, by name (compared without case).</summary>
    public sealed class StorageProviderRegistry : IStorageProviderRegistry
    {
        private readonly Dictionary<string, IStorageProvider> _providers = new(StringComparer.OrdinalIgnoreCase);

        public StorageProviderRegistry(IEnumerable<IStorageProvider> providers)
        {
            foreach (var provider in providers)
            {
                if (string.IsNullOrWhiteSpace(provider.Name))
                    throw new InvalidOperationException($"The storage provider {provider.GetType().Name} has no name.");
                if (!_providers.TryAdd(provider.Name, provider))
                    throw new InvalidOperationException($"Two storage providers have the name '{provider.Name}'.");
            }
        }

        public IReadOnlyCollection<IStorageProvider> Providers => _providers.Values;

        public IStorageProvider Get(string name)
        {
            if (name != null && _providers.TryGetValue(name, out var provider))
                return provider;
            var known = _providers.Count == 0 ? "none" : string.Join(", ", _providers.Keys.Order(StringComparer.Ordinal));
            throw new KeyNotFoundException($"No storage provider '{name}' is registered (registered: {known}).");
        }
    }
}
