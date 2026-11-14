using System.Text.Json.Nodes;
using SshServer.Administration;
using SshServer.Api.Endpoints;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.Users;
using SshServer.Interfaces.Webhooks;
using SshServer.Webhooks;
using SshServerModule.Storage;

namespace SshServer.Api.Dump;

/// <summary>
/// The dump and load of the REST API (#67) over the same services as the admin UI: roles and administrators
/// (<see cref="AdminAdministrationService"/>), virtual folders, users and settings (the scoped repository and services),
/// and webhooks (<see cref="WebhookAdministrationService"/>). Both need <see cref="AdminPermissions.SuperAdmin"/>, because
/// a dump has the password hashes of every administrator and user. Groups (#61), quotas (#62) and event rules (#68) are
/// added here when they exist.
/// </summary>
public sealed class DumpService
{
    private readonly CurrentAdmin _current;
    private readonly AdminAdministrationService _admins;
    private readonly AdminScopedSettingsRepository _repository;
    private readonly VirtualFolderService _folders;
    private readonly UserAdministrationService _users;
    private readonly UserResource _userResource;
    private readonly StorageConfigService _storage;
    private readonly WebhookAdministrationService _webhooks;
    private readonly WebhookSecretProtector _webhookSecrets;
    private readonly TimeProvider _time;

    public DumpService(CurrentAdmin current, AdminAdministrationService admins, AdminScopedSettingsRepository repository,
        VirtualFolderService folders, UserAdministrationService users, UserResource userResource, StorageConfigService storage,
        WebhookAdministrationService webhooks, WebhookSecretProtector webhookSecrets, TimeProvider time)
    {
        _current = current;
        _admins = admins;
        _repository = repository;
        _folders = folders;
        _users = users;
        _userResource = userResource;
        _storage = storage;
        _webhooks = webhooks;
        _webhookSecrets = webhookSecrets;
        _time = time;
    }

    public async Task<DumpDocument> DumpAsync(string? passphrase, CancellationToken ct)
    {
        var actor = _current.Actor;
        actor.Demand(AdminPermissions.SuperAdmin);
        DumpSecretCipher? cipher = null;
        DumpSecrets? header = null;
        if (!string.IsNullOrEmpty(passphrase))
        {
            var error = DumpSecretCipher.ValidatePassphrase(passphrase);
            if (error != null)
                throw new ApiValidationException("passphrase", error);
            cipher = DumpSecretCipher.Create(passphrase, out header);
        }

        var omitted = new List<string>();
        string? Secret(string owner, string option, string text)
        {
            if (cipher != null)
                return cipher.Protect(text);
            omitted.Add($"{owner}/{option}");
            return null;
        }

        var roles = await _admins.ListRolesAsync(actor, ct);
        var roleNames = roles.ToDictionary(r => r.Id, r => r.Name);
        var folders = _repository.GetVirtualFolders();
        var folderNames = folders.ToDictionary(f => f.Id, f => f.Name);

        return new DumpDocument
        {
            CreatedAt = _time.GetUtcNow(),
            Secrets = header,
            OmittedSecrets = omitted,
            Roles = roles.Select(r => new DumpRole(r.Name, r.Description)).ToList(),
            Admins = (await _admins.ListAdminsAsync(actor, ct)).Select(a => new DumpAdmin(a.Username, a.PasswordHash, a.Email, a.Status,
                PermissionNames.Of(a.Permissions).ToList(), a.AllowedIps?.ToList() ?? [],
                a.ScopeRoleId is { } r ? roleNames.GetValueOrDefault(r) : null, a.MustChangePassword)).ToList(),
            VirtualFolders = folders.Select(f => new DumpVirtualFolder(f.Name, f.Description,
                ExportStorage(f.Storage, (option, text) => Secret($"virtualFolders/{f.Name}", option, text)))).ToList(),
            Users = _repository.GetAllUsers().OrderBy(u => u.Username, StringComparer.OrdinalIgnoreCase).Select(u => new DumpUser(
                u.Username, u.UserRootDirectory ?? "", u.HashedPassword, u.PublicKeys?.ToList() ?? [],
                AuthMethodNames.Of(u.AllowedAuthMethods).ToList(), (u.RequireAllOf ?? []).Select(AuthMethodRules.ToSshName).ToList(),
                u.OnlyWhitelistedIps, u.WhitelistedIps?.ToList() ?? [],
                UserWrite.PermissionsOf(u).ToDictionary(p => p.Key, p => p.Value.ToList(), StringComparer.Ordinal),
                (u.PathFilters ?? []).ToDictionary(p => p.Key, p => PathFilterModel.From(p.Value), StringComparer.Ordinal),
                u.Storage is { } storage ? ExportStorage(storage, (option, text) => Secret($"users/{u.Username}", option, text)) : null,
                (u.VirtualFolders ?? []).Select(m => new DumpMount(folderNames.GetValueOrDefault(m.VirtualFolderId) ?? "", m.MountPath)).ToList(),
                u.RoleId is { } role ? roleNames.GetValueOrDefault(role) : null)).ToList(),
            Webhooks = (await _webhooks.ListAsync(ct)).Select(w => new DumpWebhook(w.Name, w.Url, w.Method,
                w.ProtectedSecret is { } secret && _webhookSecrets.TryUnprotect(secret) is { } plain ? Secret($"webhooks/{w.Name}", "secret", plain) : null,
                new Dictionary<string, string>(w.Headers), [.. w.EventTypes], [.. w.Users], w.PathGlob, w.Sync, w.FailOpen, w.TimeoutSeconds,
                w.Enabled)).ToList(),
            Settings = SettingsModel.From(_repository.ServerSettings),
        };
    }

    public async Task<LoadReport> LoadAsync(DumpDocument dump, LoadMode mode, string? passphrase, CancellationToken ct)
    {
        var actor = _current.Actor;
        actor.Demand(AdminPermissions.SuperAdmin);
        if (dump.Format != DumpDocument.FormatName || dump.Version != DumpDocument.CurrentVersion)
            throw new ApiValidationException("format", $"This is not a {DumpDocument.FormatName} version {DumpDocument.CurrentVersion}.");
        DumpSecretCipher? cipher = null;
        if (dump.Secrets != null)
        {
            if (string.IsNullOrEmpty(passphrase))
                throw new ApiValidationException("passphrase", "The dump has encrypted secrets: give its passphrase (X-Dump-Passphrase).");
            cipher = DumpSecretCipher.Open(passphrase, dump.Secrets);
        }
        string Secret(string text) => cipher?.Unprotect(text) ?? throw new ArgumentException("The dump has a secret but no passphrase header.");

        var report = new Report(mode);
        await LoadRolesAsync(actor, dump, report, ct);
        var roleIds = (await _admins.ListRolesAsync(actor, ct)).ToDictionary(r => r.Name, r => r.Id, StringComparer.OrdinalIgnoreCase);
        LoadFolders(dump, report, Secret);
        var folderIds = _repository.GetVirtualFolders().ToDictionary(f => f.Name, f => f.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var user in dump.Users ?? [])
            await report.RunAsync($"user {user.Username}", () => LoadUserAsync(user, roleIds, folderIds, mode, Secret, ct));
        foreach (var admin in dump.Admins ?? [])
            await report.RunAsync($"administrator {admin.Username}", () => LoadAdminAsync(actor, admin, roleIds, mode, ct));
        foreach (var webhook in dump.Webhooks ?? [])
            await report.RunAsync($"webhook {webhook.Name}", () => LoadWebhookAsync(webhook, mode, cipher, ct));
        if (dump.Settings != null)
        {
            await report.RunAsync("settings", () =>
            {
                if (mode != LoadMode.Update)
                    return Task.FromResult(Outcome.Skipped);
                var settings = _repository.ServerSettings;
                dump.Settings.ApplyTo(settings);
                return Task.FromResult(_repository.UpdateServerSettings(settings) ? Outcome.Updated : throw new InvalidOperationException("not saved"));
            });
        }
        return report.ToReport();
    }

    private async Task LoadRolesAsync(AdminActor actor, DumpDocument dump, Report report, CancellationToken ct)
    {
        var existing = (await _admins.ListRolesAsync(actor, ct)).ToDictionary(r => r.Name, StringComparer.OrdinalIgnoreCase);
        foreach (var role in dump.Roles ?? [])
        {
            await report.RunAsync($"role {role.Name}", async () =>
            {
                if (!existing.TryGetValue(role.Name ?? "", out var stored))
                {
                    await _admins.CreateRoleAsync(actor, role.Name ?? "", role.Description, ct);
                    return Outcome.Added;
                }
                if (report.Exists())
                    return Outcome.Skipped;
                await _admins.UpdateRoleAsync(actor, new Role { Id = stored.Id, Name = stored.Name, Description = role.Description }, ct);
                return Outcome.Updated;
            });
        }
    }

    private void LoadFolders(DumpDocument dump, Report report, Func<string, string> secret)
    {
        foreach (var folder in dump.VirtualFolders ?? [])
        {
            report.Run($"virtual folder {folder.Name}", () =>
            {
                var nameError = VirtualFolderService.ValidateName(folder.Name);
                if (nameError != null)
                    throw new ApiValidationException("name", nameError);
                var stored = _repository.GetVirtualFolders().FirstOrDefault(f => string.Equals(f.Name, folder.Name.Trim(), StringComparison.OrdinalIgnoreCase));
                if (stored != null && report.Exists())
                    return Outcome.Skipped;
                var storage = ImportStorage(folder.Storage, secret) ?? throw new ApiValidationException("storage", "A virtual folder needs a storage.");
                var saved = new VirtualFolder { Id = stored?.Id ?? 0, Name = folder.Name, Description = folder.Description, Storage = storage };
                if (stored == null)
                    return _folders.TryAdd(saved) ? Outcome.Added : throw new ApiConflictException("The name is used.");
                return _folders.TryUpdate(saved) ? Outcome.Updated : throw new ApiConflictException("The folder could not be saved.");
            });
        }
    }

    private async Task<Outcome> LoadUserAsync(DumpUser dumped, Dictionary<string, int> roleIds, Dictionary<string, int> folderIds, LoadMode mode,
        Func<string, string> secret, CancellationToken ct)
    {
        var stored = _userResource.Get(dumped.Username ?? "");
        if (stored != null && mode != LoadMode.Update)
            return mode == LoadMode.Skip ? Outcome.Skipped : throw new ApiConflictException("It exists already.");
        if (dumped.PasswordHash != null && !PasswordHasher.IsWellFormed(dumped.PasswordHash))
            throw new ApiValidationException("passwordHash", "The password hash is not valid.");

        var mounts = new List<VirtualFolderMountModel>();
        foreach (var mount in dumped.VirtualFolders ?? [])
        {
            if (!folderIds.TryGetValue(mount.VirtualFolder ?? "", out var id))
                throw new ApiValidationException("virtualFolders", $"The virtual folder '{mount.VirtualFolder}' is not in the dump or on the server.");
            mounts.Add(new VirtualFolderMountModel(id, mount.MountPath));
        }
        int? roleId = null;
        if (dumped.Role != null)
            roleId = roleIds.TryGetValue(dumped.Role, out var id) ? id : throw new ApiValidationException("role", $"The role '{dumped.Role}' does not exist.");

        var write = new UserWrite
        {
            Username = dumped.Username,
            RootDirectory = dumped.RootDirectory,
            AllowedAuthMethods = dumped.AllowedAuthMethods,
            RequireAllOf = dumped.RequireAllOf,
            OnlyWhitelistedIps = dumped.OnlyWhitelistedIps,
            WhitelistedIps = dumped.WhitelistedIps,
            Permissions = dumped.Permissions,
            PathFilters = dumped.PathFilters,
            VirtualFolders = mounts,
            RoleId = roleId,
        };
        var user = stored ?? new User();
        await _userResource.ApplyAsync(write, user, stored == null, errors =>
        {
            try
            {
                return ImportStorage(dumped.Storage, secret);
            }
            catch (ApiValidationException ex)
            {
                foreach (var (field, problems) in ex.Errors)
                    errors.AddRange(field, problems);
                return null;
            }
        }, ct);
        user.HashedPassword = dumped.PasswordHash;
        user.PublicKeys = dumped.PublicKeys?.ToList();

        if (stored == null)
            return _users.TryAdd(user) ? Outcome.Added : throw new ApiConflictException("It could not be added.");
        return _repository.UpdateUser(user) ? Outcome.Updated : throw new ApiConflictException("It could not be saved.");
    }

    private async Task<Outcome> LoadAdminAsync(AdminActor actor, DumpAdmin dumped, Dictionary<string, int> roleIds, LoadMode mode, CancellationToken ct)
    {
        var exists = (await _admins.ListAdminsAsync(actor, ct)).Any(a => string.Equals(a.Username, dumped.Username, StringComparison.OrdinalIgnoreCase));
        // The caller is never replaced by the dump: it keeps its own login.
        if (string.Equals(dumped.Username, actor.Username, StringComparison.OrdinalIgnoreCase))
            return Outcome.Skipped;
        if (exists && mode != LoadMode.Update)
            return mode == LoadMode.Skip ? Outcome.Skipped : throw new ApiConflictException("It exists already.");

        int? scope = null;
        if (dumped.ScopeRole != null)
            scope = roleIds.TryGetValue(dumped.ScopeRole, out var id) ? id : throw new ApiValidationException("scopeRole", $"The role '{dumped.ScopeRole}' does not exist.");
        var write = new AdminWrite
        {
            Email = dumped.Email,
            Status = dumped.Status,
            Permissions = dumped.Permissions,
            AllowedIps = dumped.AllowedIps,
            ScopeRoleId = scope,
            MustChangePassword = dumped.MustChangePassword,
        };
        var replaced = await _admins.LoadAdminAsync(actor, write.ToInput(dumped.Username ?? ""), dumped.PasswordHash ?? "", ct);
        return replaced ? Outcome.Updated : Outcome.Added;
    }

    private async Task<Outcome> LoadWebhookAsync(DumpWebhook dumped, LoadMode mode, DumpSecretCipher? cipher, CancellationToken ct)
    {
        var stored = (await _webhooks.ListAsync(ct)).FirstOrDefault(w => string.Equals(w.Name, dumped.Name, StringComparison.OrdinalIgnoreCase));
        if (stored != null && mode != LoadMode.Update)
            return mode == LoadMode.Skip ? Outcome.Skipped : throw new ApiConflictException("It exists already.");
        string? secret = null;
        if (dumped.Secret != null)
            secret = cipher?.Unprotect(dumped.Secret) ?? throw new ArgumentException("The dump has a secret but no passphrase header.");
        var result = await _webhooks.SaveAsync(new WebhookInput
        {
            Id = stored?.Id,
            Name = dumped.Name ?? "",
            Url = dumped.Url ?? "",
            Method = dumped.Method ?? Webhook.MethodPost,
            NewSecret = secret,
            Headers = dumped.Headers ?? [],
            EventTypes = dumped.EventTypes ?? [],
            Users = dumped.Users ?? [],
            PathGlob = dumped.PathGlob,
            Sync = dumped.Sync,
            FailOpen = dumped.FailOpen,
            TimeoutSeconds = dumped.TimeoutSeconds,
            Enabled = dumped.Enabled,
        }, ct);
        if (!result.Succeeded)
            throw new ApiValidationException("", string.Join(" ", result.Errors));
        return stored == null ? Outcome.Added : Outcome.Updated;
    }

    private DumpStorage ExportStorage(StorageConfig storage, Func<string, string, string?> secret) =>
        new(storage.Provider, _storage.Export(storage, secret));

    private StorageConfig? ImportStorage(DumpStorage? storage, Func<string, string> secret)
    {
        if (storage == null)
            return null;
        var result = _storage.Import(storage.Provider ?? "", storage.Options ?? new JsonObject(), secret);
        if (!result.IsValid)
            throw new ApiValidationException("storage", string.Join(" ", result.Problems));
        return result.Config;
    }

    private enum Outcome
    {
        Added,
        Updated,
        Skipped,
    }

    /// <summary>Counts the outcomes; a failed object is an error of the report, and the load goes on with the next one.</summary>
    private sealed class Report
    {
        private readonly LoadMode _mode;
        private readonly List<string> _errors = new();
        private int _added;
        private int _updated;
        private int _skipped;

        public Report(LoadMode mode)
        {
            _mode = mode;
        }

        /// <summary>True when an existing object is not replaced (it is skipped, or an error in <see cref="LoadMode.Add"/>).</summary>
        public bool Exists()
        {
            if (_mode == LoadMode.Add)
                throw new ApiConflictException("It exists already.");
            return _mode == LoadMode.Skip;
        }

        public void Run(string name, Func<Outcome> load) => RunAsync(name, () => Task.FromResult(load())).GetAwaiter().GetResult();

        public async Task RunAsync(string name, Func<Task<Outcome>> load)
        {
            try
            {
                Count(await load());
            }
            catch (ApiValidationException ex)
            {
                _errors.Add($"The {name} was not loaded: {string.Join(" ", ex.Errors.SelectMany(e => e.Value))}");
            }
            catch (Exception ex) when (ex is ApiConflictException or AdminAdministrationException or AdminAccessDeniedException
                                           or UserAdministrationException or ArgumentException or InvalidOperationException)
            {
                _errors.Add($"The {name} was not loaded: {ex.Message}");
            }
        }

        public LoadReport ToReport() => new(_mode, _added, _updated, _skipped, _errors);

        private void Count(Outcome outcome)
        {
            switch (outcome)
            {
                case Outcome.Added:
                    _added++;
                    break;
                case Outcome.Updated:
                    _updated++;
                    break;
                default:
                    _skipped++;
                    break;
            }
        }
    }
}
