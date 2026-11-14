using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace SshServer.Api.Endpoints;

/// <summary>
/// A stored storage configuration (#56) in the API: the provider, the options that are not secret, and the names of
/// the secrets that have a stored value. A secret is never returned.
/// </summary>
public sealed record StorageView(string Provider, string DisplayName, IReadOnlyDictionary<string, JsonNode?> Options,
    IReadOnlyList<string> StoredSecrets, string? Problem);

/// <summary>
/// A storage configuration to save. <see cref="Options"/> has the option values by name (see
/// <c>GET /api/v1/storage-providers</c>); an option that is not given gets its default value, except a secret, which
/// keeps its stored value (remove it with <see cref="ClearSecrets"/>). No provider (or an empty one): the default
/// storage, the local disk at the root directory of the user.
/// </summary>
public sealed record StorageWrite
{
    public string? Provider { get; init; }

    public Dictionary<string, JsonElement>? Options { get; init; }

    public List<string>? ClearSecrets { get; init; }
}

/// <summary>A registered storage provider and its options, for clients that build a storage configuration.</summary>
public sealed record StorageProviderView(string Name, string DisplayName, string? Description, IReadOnlyList<StorageOptionView> Options);

public sealed record StorageOptionView(string Name, string Label, string? Description, string Kind, bool Secret, IReadOnlyList<string> Choices);

/// <summary>Maps the storage configurations between the API and <see cref="StorageConfigService"/>, the service of the admin UI.</summary>
public sealed class StorageMapper
{
    private readonly StorageConfigService _service;

    public StorageMapper(StorageConfigService service)
    {
        _service = service;
    }

    public IReadOnlyList<StorageProviderView> Providers() => _service.Providers
        .Select(p => new StorageProviderView(p.Name, p.DisplayName, p.Description, p.Fields
            .Select(f => new StorageOptionView(f.Name, f.Label, f.Description, f.Kind.ToString(), f.IsSecret, f.Choices))
            .ToList()))
        .ToList();

    /// <summary>The view of a stored configuration; null for the default storage.</summary>
    public StorageView? View(StorageConfig? stored)
    {
        if (stored is null)
            return null;
        var settings = _service.Edit(stored);
        var info = _service.Find(settings.Provider);
        var options = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
        foreach (var field in info?.Fields ?? [])
        {
            if (!field.IsSecret && settings.Values.TryGetValue(field.Name, out var text) && text.Length > 0)
                options[field.Name] = Typed(field, text);
        }
        return new StorageView(settings.Provider, info?.DisplayName ?? settings.Provider, options,
            settings.StoredSecrets.OrderBy(s => s, StringComparer.Ordinal).ToList(), settings.LoadProblem);
    }

    /// <summary>The write model of a stored configuration (for a PATCH): the view without the secrets.</summary>
    public StorageWrite? WriteModel(StorageConfig? stored)
    {
        var view = View(stored);
        if (view is null)
            return null;
        return new StorageWrite
        {
            Provider = view.Provider,
            Options = view.Options.ToDictionary(o => o.Key, o => JsonSerializer.SerializeToElement(o.Value), StringComparer.Ordinal),
        };
    }

    /// <summary>
    /// The configuration to store, or null for the default storage. The problems go to <paramref name="errors"/> under
    /// <paramref name="field"/>.
    /// </summary>
    public StorageConfig? Build(StorageWrite? write, StorageConfig? stored, ValidationErrors errors, string field)
    {
        var settings = ToSettings(write, stored, errors, field);
        if (settings is null)
            return null;
        var result = _service.Build(settings);
        errors.AddRange(field, result.Problems);
        return result.Config;
    }

    /// <summary>Creates the storage of <paramref name="write"/> (not saved) and lists its root, like the test button of the admin UI.</summary>
    public async Task<StorageTestResult> TestAsync(StorageWrite write, StorageConfig? stored, CancellationToken ct)
    {
        var errors = new ValidationErrors();
        var settings = ToSettings(write, stored, errors, "storage");
        errors.ThrowIfAny();
        if (settings is null)
            throw new ApiValidationException("storage.provider", "Select a storage provider.");
        return await _service.TestAsync(settings, ct);
    }

    private StorageSettings? ToSettings(StorageWrite? write, StorageConfig? stored, ValidationErrors errors, string field)
    {
        if (write is null || string.IsNullOrWhiteSpace(write.Provider))
            return null;
        var info = _service.Find(write.Provider.Trim());
        if (info is null)
        {
            errors.Add(field + ".provider", $"The storage provider '{write.Provider}' is not registered.");
            return null;
        }

        var settings = _service.Edit(stored);
        if (!string.Equals(settings.Provider, info.Name, StringComparison.OrdinalIgnoreCase) || settings.LoadProblem != null)
            _service.SelectProvider(settings, info.Name);
        var defaults = new StorageSettings();
        _service.SelectProvider(defaults, info.Name);

        var given = new Dictionary<string, JsonElement>(write.Options ?? [], StringComparer.OrdinalIgnoreCase);
        foreach (var unknown in given.Keys.Where(k => !info.Fields.Any(f => string.Equals(f.Name, k, StringComparison.OrdinalIgnoreCase))))
            errors.Add($"{field}.options.{unknown}", $"The storage provider '{info.Name}' has no option '{unknown}'.");

        foreach (var option in info.Fields)
        {
            var has = given.TryGetValue(option.Name, out var value);
            string text;
            if (!has)
                text = option.IsSecret ? "" : defaults.Value(option.Name);
            else if (!TryText(value, out text))
            {
                errors.Add($"{field}.options.{option.Name}", "The value must be a string, a number or true/false.");
                continue;
            }
            settings.Values[option.Name] = text;
        }

        foreach (var secret in write.ClearSecrets ?? [])
        {
            var match = info.Fields.FirstOrDefault(f => f.IsSecret && string.Equals(f.Name, secret, StringComparison.OrdinalIgnoreCase));
            if (match is null)
                errors.Add(field + ".clearSecrets", $"'{secret}' is not a secret option of '{info.Name}'.");
            else
                settings.ClearSecrets.Add(match.Name);
        }
        return settings;
    }

    private static bool TryText(JsonElement value, out string text)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.String:
                text = value.GetString() ?? "";
                return true;
            case JsonValueKind.True:
                text = "true";
                return true;
            case JsonValueKind.False:
                text = "false";
                return true;
            case JsonValueKind.Number:
                text = value.GetRawText();
                return true;
            case JsonValueKind.Null:
                text = "";
                return true;
            default:
                text = "";
                return false;
        }
    }

    private static JsonNode? Typed(StorageOptionField field, string text) => field.Kind switch
    {
        StorageOptionKind.Boolean => JsonValue.Create(string.Equals(text, "true", StringComparison.OrdinalIgnoreCase)),
        StorageOptionKind.Number when long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) => JsonValue.Create(number),
        _ => JsonValue.Create(text),
    };
}
