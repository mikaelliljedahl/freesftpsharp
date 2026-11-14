using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using SshServer.Administration;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Api;
using SshServer.Interfaces.Events;

namespace SshServer.Api.ApiKeys;

/// <summary>An API key with the name of its owner, for the API and the provider events (never the key or its hash).</summary>
public sealed record ApiKeySnapshot(int Id, string Name, string Prefix, string Owner, IReadOnlyList<string>? Scopes,
    DateTime CreatedAt, DateTime? ExpiresAt, DateTime? LastUsedAt);

/// <summary>A new API key: the key itself is in <see cref="Key"/> only here, once.</summary>
public sealed record CreatedApiKey(ApiKeySnapshot ApiKey, string Key);

/// <summary>
/// The one service for the REST API keys (#67): create, list, revoke, and the check of a key in a request. The rules:
/// <list type="bullet">
/// <item>An administrator creates keys for itself; the key acts with the current permissions and scope of its owner,
/// narrowed by the scopes of the key. It cannot have a scope that the owner does not have.</item>
/// <item>An administrator lists and revokes its own keys. One with <see cref="AdminPermissions.ManageAdmins"/> also those
/// of the administrators it may manage (not those of an administrator with more permissions).</item>
/// <item>A request signed in with an API key cannot create or revoke keys, so a leaked key cannot make new ones.</item>
/// <item>Only the SHA-256 hash of a key is stored. A key of a disabled or removed administrator, an expired key, or a
/// request from an address that the owner may not log in from is refused.</item>
/// </list>
/// Every change is published as a <see cref="ProviderEvent"/> with the actor.
/// </summary>
public sealed class ApiKeyService
{
    public const string KeyPrefix = "fss_";
    public const int MaximumNameLength = 100;
    private const int PrefixLength = 12;
    private static readonly TimeSpan TouchInterval = TimeSpan.FromMinutes(1);

    private readonly IApiKeyStore _keys;
    private readonly IAdminStore _admins;
    private readonly TimeProvider _time;
    private readonly IEventBus? _events;

    public ApiKeyService(IApiKeyStore keys, IAdminStore admins, TimeProvider time, IEventBus? events = null)
    {
        _keys = keys;
        _admins = admins;
        _time = time;
        _events = events;
    }

    /// <summary>The keys of the actor, or with <paramref name="all"/> every key it may manage.</summary>
    public async Task<IReadOnlyList<ApiKeySnapshot>> ListAsync(AdminActor actor, bool all, CancellationToken ct)
    {
        var self = await GetSelfAsync(actor, ct);
        var admins = (await _admins.ListAdminsAsync(ct)).ToDictionary(a => a.Id);
        if (!all)
            return (await _keys.ListAsync(self.Id, ct)).Select(k => Snapshot(k, self.Username)).ToList();

        actor.Demand(AdminPermissions.ManageAdmins);
        return (await _keys.ListAsync(null, ct))
            .Where(k => admins.TryGetValue(k.AdminId, out var owner) && (owner.Id == self.Id || CanManage(actor, owner)))
            .Select(k => Snapshot(k, admins[k.AdminId].Username))
            .ToList();
    }

    public async Task<CreatedApiKey> CreateAsync(AdminActor actor, string? name, DateTime? expiresAtUtc, AdminPermissions? scopes, CancellationToken ct)
    {
        DemandNotApiKey(actor);
        var self = await GetSelfAsync(actor, ct);
        var trimmed = name?.Trim() ?? "";
        if (trimmed.Length == 0)
            throw new AdminAdministrationException("Enter a name for the API key.");
        if (trimmed.Length > MaximumNameLength)
            throw new AdminAdministrationException($"The name of the API key can have at most {MaximumNameLength} characters.");
        var now = _time.GetUtcNow().UtcDateTime;
        if (expiresAtUtc is { } expires && ApiTime.ToUtc(expires) <= now)
            throw new AdminAdministrationException("The expiry of the API key must be in the future.");
        if (scopes is { } mask)
        {
            if (mask == AdminPermissions.None || (mask & ~AdminPermissionRules.Everything) != AdminPermissions.None)
                throw new AdminAdministrationException("The scopes of an API key are one or more admin permissions.");
            var missing = mask & ~actor.Permissions;
            if (missing != AdminPermissions.None)
                throw new AdminAccessDeniedException($"An API key cannot have permissions that you do not have: {missing}.");
        }

        var key = KeyPrefix + Base64Url(RandomNumberGenerator.GetBytes(32));
        var apiKey = new ApiKey
        {
            Name = trimmed,
            Prefix = key[..PrefixLength],
            KeyHash = Hash(key),
            AdminId = self.Id,
            Scopes = scopes,
            CreatedAt = now,
            ExpiresAt = ApiTime.ToUtc(expiresAtUtc),
        };
        if (!await _keys.AddAsync(apiKey, ct))
            throw new AdminAdministrationException($"You have an API key with the name '{trimmed}' already.");

        var snapshot = Snapshot(apiKey, self.Username);
        await PublishAsync(ProviderAction.Add, actor, snapshot);
        return new CreatedApiKey(snapshot, key);
    }

    /// <summary>Revokes a key. False when there is no such key or the actor may not see it.</summary>
    public async Task<bool> RevokeAsync(AdminActor actor, int id, CancellationToken ct)
    {
        DemandNotApiKey(actor);
        var self = await GetSelfAsync(actor, ct);
        var key = await _keys.GetAsync(id, ct);
        if (key == null)
            return false;
        var owner = (await _admins.ListAdminsAsync(ct)).FirstOrDefault(a => a.Id == key.AdminId);
        if (owner == null || (owner.Id != self.Id && !(actor.Has(AdminPermissions.ManageAdmins) && CanManage(actor, owner))))
            return false;
        if (!await _keys.RemoveAsync(id, ct))
            return false;
        await PublishAsync(ProviderAction.Delete, actor, Snapshot(key, owner.Username));
        return true;
    }

    /// <summary>
    /// The claims of a request with this key (<see cref="AdminClaims.CreateClaims"/> of the owner, narrowed by the scopes),
    /// or null when the key is not valid now.
    /// </summary>
    public async Task<IReadOnlyList<Claim>?> AuthenticateAsync(string key, IPAddress? client, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(key) || !key.StartsWith(KeyPrefix, StringComparison.Ordinal))
            return null;
        var stored = await _keys.FindByHashAsync(Hash(key), ct);
        var now = _time.GetUtcNow().UtcDateTime;
        if (stored == null || stored.IsExpired(now))
            return null;
        var owner = (await _admins.ListAdminsAsync(ct)).FirstOrDefault(a => a.Id == stored.AdminId);
        if (owner == null || owner.Status != AdminStatus.Enabled || !AdminClaims.IsAddressAllowed(owner, client))
            return null;

        if (stored.LastUsedAt is not { } last || now - last >= TouchInterval)
            await _keys.TouchAsync(stored.Id, now, ct);
        return AdminClaims.CreateClaims(owner, stored.Scopes, stored.Name);
    }

    /// <summary>The lower-case hex SHA-256 of a key.</summary>
    public static string Hash(string key) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key)));

    private async Task<Admin> GetSelfAsync(AdminActor actor, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(actor.Username) || actor.IsSystem)
            throw new AdminAccessDeniedException("You are not logged in.");
        return await _admins.GetAdminAsync(actor.Username, ct)
               ?? throw new AdminAccessDeniedException("You are not logged in.");
    }

    private static void DemandNotApiKey(AdminActor actor)
    {
        if (actor.ApiKeyName != null)
            throw new AdminAccessDeniedException("An API key cannot create or revoke API keys. Use a bearer token.");
    }

    private static bool CanManage(AdminActor actor, Admin owner) => (owner.Permissions & ~actor.Permissions) == AdminPermissions.None;

    private static ApiKeySnapshot Snapshot(ApiKey key, string owner) => new(key.Id, key.Name, key.Prefix, owner,
        key.Scopes is { } scopes ? PermissionNames.Of(scopes) : null, key.CreatedAt, key.ExpiresAt, key.LastUsedAt);

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private Task PublishAsync(ProviderAction action, AdminActor actor, ApiKeySnapshot key) =>
        _events?.PublishAsync(new ProviderEvent(action, ProviderObjectType.ApiKey, $"{key.Owner}/{key.Name}")
        {
            Timestamp = _time.GetUtcNow(),
            Actor = actor.AuditName,
            Object = key with { LastUsedAt = null },
        }, CancellationToken.None).AsTask() ?? Task.CompletedTask;
}
