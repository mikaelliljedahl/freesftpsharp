using System.Text.Json.Nodes;
using SshServer.Api.Endpoints;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Authentication;

namespace SshServer.Api.Dump;

/// <summary>
/// The provider-independent export of the stored objects (<c>GET /api/v1/dump</c>), for backup, migration and
/// infrastructure as code. Objects refer to each other by name, not by id. Passwords are their hashes; the secrets of
/// storages and webhooks are in the dump only when the caller gives a passphrase (<see cref="Secrets"/>), encrypted with it.
/// </summary>
public sealed record DumpDocument
{
    public const string FormatName = "freesftpsharp-dump";
    public const int CurrentVersion = 1;

    public string Format { get; init; } = FormatName;

    public int Version { get; init; } = CurrentVersion;

    public DateTimeOffset CreatedAt { get; init; }

    /// <summary>How the secrets are encrypted; null when the dump has no secrets.</summary>
    public DumpSecrets? Secrets { get; init; }

    /// <summary>The secrets that are not in the dump (no passphrase was given), as "object/option".</summary>
    public List<string> OmittedSecrets { get; init; } = [];

    public List<DumpRole> Roles { get; init; } = [];

    public List<DumpAdmin> Admins { get; init; } = [];

    public List<DumpVirtualFolder> VirtualFolders { get; init; } = [];

    public List<DumpUser> Users { get; init; } = [];

    public List<DumpWebhook> Webhooks { get; init; } = [];

    public SettingsModel? Settings { get; init; }
}

/// <summary>The key derivation of the secrets: PBKDF2-SHA256 of the passphrase with the salt; <see cref="Check"/> tells a wrong passphrase.</summary>
public sealed record DumpSecrets(string Kdf, int Iterations, string Salt, string Check);

public sealed record DumpRole(string Name, string? Description);

public sealed record DumpAdmin(string Username, string PasswordHash, string? Email, AdminStatus Status, List<string> Permissions,
    List<string> AllowedIps, string? ScopeRole, bool MustChangePassword);

/// <summary>A storage: the provider and all its options (secrets encrypted with the passphrase, or left out).</summary>
public sealed record DumpStorage(string Provider, JsonObject Options);

public sealed record DumpVirtualFolder(string Name, string? Description, DumpStorage Storage);

public sealed record DumpMount(string VirtualFolder, string MountPath);

public sealed record DumpUser(string Username, string RootDirectory, string? PasswordHash, List<PublicKeyEntry> PublicKeys,
    List<string> AllowedAuthMethods, List<string> RequireAllOf, bool OnlyWhitelistedIps, List<string> WhitelistedIps,
    Dictionary<string, List<string>> Permissions, Dictionary<string, PathFilterModel> PathFilters, DumpStorage? Storage,
    List<DumpMount> VirtualFolders, string? Role);

public sealed record DumpWebhook(string Name, string Url, string Method, string? Secret, Dictionary<string, string> Headers,
    List<string> EventTypes, List<string> Users, string? PathGlob, bool Sync, bool FailOpen, int TimeoutSeconds, bool Enabled);

/// <summary>What to do with an object of the dump that exists already.</summary>
public enum LoadMode
{
    /// <summary>Add the new objects; an existing one is an error and stays as it is.</summary>
    Add,

    /// <summary>Add the new objects and replace the existing ones (and save the settings).</summary>
    Update,

    /// <summary>Add the new objects and leave the existing ones as they are.</summary>
    Skip,
}

/// <summary>The result of a load.</summary>
public sealed record LoadReport(LoadMode Mode, int Added, int Updated, int Skipped, IReadOnlyList<string> Errors);
