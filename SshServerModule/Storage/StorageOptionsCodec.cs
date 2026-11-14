#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Storage
{
    /// <summary>
    /// Converts between the options object of a storage provider and the stored <see cref="StorageConfig"/>: JSON of the
    /// <see cref="IStorageProvider.OptionsType"/> of the provider, with every <see cref="SecretAttribute"/> property
    /// encrypted by <see cref="ISecretProtector"/>. The core never looks into the options of a provider; the provider
    /// validates them (<see cref="IStorageProvider.Validate"/>).
    /// </summary>
    public sealed class StorageOptionsCodec
    {
        private static readonly JsonSerializerOptions Json = new()
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() },
        };

        private static readonly JsonNodeOptions NodeOptions = new() { PropertyNameCaseInsensitive = true };

        private readonly IStorageProviderRegistry _registry;
        private readonly ISecretProtector _secrets;

        public StorageOptionsCodec(IStorageProviderRegistry registry, ISecretProtector secrets)
        {
            _registry = registry;
            _secrets = secrets;
        }

        /// <summary>The stored form of <paramref name="options"/> (of the options type of the provider), with the secrets encrypted.</summary>
        public StorageConfig Encode(string provider, object options)
        {
            var storageProvider = _registry.Get(provider);
            if (!storageProvider.OptionsType.IsInstanceOfType(options))
                throw new ArgumentException($"The options of the storage provider '{storageProvider.Name}' must be a {storageProvider.OptionsType.Name}.", nameof(options));

            var node = ToNode(options, storageProvider.OptionsType);
            foreach (var secret in Secrets(storageProvider))
            {
                if (node[secret.Name] is JsonValue value && value.TryGetValue<string>(out var text) && text.Length > 0)
                    node[secret.Name] = _secrets.Protect(text);
            }
            return new StorageConfig { Provider = storageProvider.Name, Options = node.ToJsonString() };
        }

        /// <summary>
        /// The options object of a stored configuration, with the secrets decrypted. Throws <see cref="ArgumentException"/>
        /// when the provider is not registered, the options cannot be read or a secret cannot be decrypted. The
        /// options are not validated here (<see cref="IStorageProvider.CreateAsync"/> does it).
        /// </summary>
        public object Decode(StorageConfig config)
        {
            var provider = ProviderOf(config);
            return FromNode(provider, DecodeNode(provider, config));
        }

        /// <summary>The options of a stored configuration as JSON, with the secrets decrypted.</summary>
        internal JsonObject DecodeNode(IStorageProvider provider, StorageConfig config)
        {
            JsonObject node;
            try
            {
                node = JsonNode.Parse(string.IsNullOrWhiteSpace(config.Options) ? "{}" : config.Options, NodeOptions) as JsonObject
                       ?? throw new ArgumentException($"The options of the storage '{provider.Name}' are not a JSON object.");
            }
            catch (JsonException ex)
            {
                throw new ArgumentException($"The options of the storage '{provider.Name}' are not valid JSON.", ex);
            }

            foreach (var secret in Secrets(provider))
            {
                if (node[secret.Name] is not JsonValue value || !value.TryGetValue<string>(out var text) || text.Length == 0)
                    continue;
                try
                {
                    node[secret.Name] = _secrets.Unprotect(text);
                }
                catch (CryptographicException ex)
                {
                    throw new ArgumentException(
                        $"The secret '{secret.Label}' of the storage '{provider.Name}' cannot be decrypted. Are the data protection keys (DataProtection:KeysPath) the same as when it was saved?", ex);
                }
            }
            return node;
        }

        /// <summary>The options object of plain JSON options. Throws <see cref="ArgumentException"/> when they do not fit the options type.</summary>
        internal static object FromNode(IStorageProvider provider, JsonObject node)
        {
            try
            {
                return node.Deserialize(provider.OptionsType, Json)
                       ?? throw new ArgumentException($"The options of the storage '{provider.Name}' are empty.");
            }
            catch (JsonException ex)
            {
                // The message of System.Text.Json names the property, not its value (it can be a secret).
                throw new ArgumentException($"The options of the storage '{provider.Name}' are not valid: {ex.Message}", ex);
            }
        }

        /// <summary>An options object as JSON, with every property (names compared without case).</summary>
        internal static JsonObject ToNode(object options, Type optionsType)
            => (JsonObject)JsonNode.Parse(JsonSerializer.Serialize(options, optionsType, Json), NodeOptions)!;

        internal IStorageProvider ProviderOf(StorageConfig config)
        {
            try
            {
                return _registry.Get(config.Provider);
            }
            catch (KeyNotFoundException ex)
            {
                throw new ArgumentException(ex.Message, ex);
            }
        }

        private static IEnumerable<StorageOptionField> Secrets(IStorageProvider provider)
            => StorageOptionField.Of(provider.OptionsType).Where(f => f.IsSecret);
    }

    /// <summary>
    /// The <see cref="ISecretProtector"/> when the host registers none (<c>AddSshServerSettings</c> registers the ASP.NET
    /// Core data protection). A storage configuration without secrets works; one with a secret cannot be saved or used.
    /// </summary>
    public sealed class UnavailableSecretProtector : ISecretProtector
    {
        public string Protect(string plaintext)
            => throw new InvalidOperationException("No secret protection is registered (AddSshServerSettings), so a secret cannot be stored.");

        public string Unprotect(string protectedValue)
            => throw new CryptographicException("No secret protection is registered (AddSshServerSettings), so a stored secret cannot be read.");
    }
}
