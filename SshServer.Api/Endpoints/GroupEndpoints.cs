using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using SshServer.Administration;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Quotas;
using SshServerModule.Storage;
using JsonOptions = Microsoft.AspNetCore.Http.Json.JsonOptions;

namespace SshServer.Api.Endpoints;

/// <summary>A group of users (#61) in the API: shared settings for its members. A setting that is null is not set by the group.</summary>
public sealed record GroupView(int Id, string Name, string? Description, IReadOnlyDictionary<string, IReadOnlyList<string>>? Permissions,
    IReadOnlyDictionary<string, PathFilterModel>? PathFilters, StorageView? Storage, IReadOnlyList<VirtualFolderMountModel> VirtualFolders,
    IReadOnlyList<string>? AllowedAuthMethods, IReadOnlyList<string>? AllowedIps, int? RoleId, DiskQuota? DiskQuota, TransferQuota? TransferQuota,
    BandwidthLimit? Bandwidth, IReadOnlyList<string> Members);

/// <summary>
/// A group to create or save. A value that is not given is not set by the group. The storage is a template:
/// <c>%username%</c> in a text option is the name of the member. Its secrets are write-only.
/// </summary>
public sealed record GroupWrite
{
    public string? Name { get; init; }

    public string? Description { get; init; }

    public Dictionary<string, List<string>>? Permissions { get; init; }

    public Dictionary<string, PathFilterModel>? PathFilters { get; init; }

    public StorageWrite? Storage { get; init; }

    public List<VirtualFolderMountModel>? VirtualFolders { get; init; }

    /// <summary>The login methods of the members whose own setting allows every method (password, publickey, keyboard-interactive).</summary>
    public List<string>? AllowedAuthMethods { get; init; }

    /// <summary>The networks the members may log in from.</summary>
    public List<string>? AllowedIps { get; init; }

    /// <summary>The scope role (#60). An administrator with a scope role always gives its own role.</summary>
    public int? RoleId { get; init; }

    /// <summary>The disk quota of the own storage of each member without one (#62).</summary>
    public DiskQuota? DiskQuota { get; init; }

    /// <summary>The transfer quota of each member without one (#62).</summary>
    public TransferQuota? TransferQuota { get; init; }

    /// <summary>The bandwidth of each member without one (#62).</summary>
    public BandwidthLimit? Bandwidth { get; init; }
}

/// <summary>A member to add: the primary group of the user, or (default) a secondary group.</summary>
public sealed record GroupMemberWrite(string? Username, bool Primary);

/// <summary>
/// /api/v1/groups over <see cref="GroupService"/> of the Groups page, with the scoped repository: administrators who
/// manage users or groups read them, one with <see cref="AdminPermissions.ManageGroups"/> changes them, and a scoped
/// administrator sees only the groups of its role. The membership is a setting of the user (ManageUsers).
/// </summary>
internal static class GroupEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        var groups = api.MapGroup("/groups").WithTags("Groups");

        groups.MapGet("/", (GroupService service, StorageMapper storage, int? offset, int? limit) =>
                TypedResults.Ok(Paging.Of(service.List(), offset, limit, g => View(g, service, storage))))
            .WithName("ListGroups").WithSummary("Lists the groups (needs ManageGroups or ManageUsers).").WithValidationErrors();

        groups.MapGet("/{id:int}", Results<Ok<GroupView>, ProblemHttpResult> (GroupService service, StorageMapper storage, int id) =>
                service.Get(id) is { } group ? TypedResults.Ok(View(group, service, storage)) : NotFound(id))
            .WithName("GetGroup").WithErrors().WithNotFound();

        groups.MapPost("/", async (GroupService service, VirtualFolderService folders, StorageMapper storage, IAdminStore admins,
                CurrentAdmin current, GroupWrite request, CancellationToken ct) =>
            {
                var group = await BuildAsync(request, new Group(), folders, storage, admins, current, ct);
                if (!service.TryAdd(group))
                    throw new ApiConflictException($"A group with the name '{group.Name}' already exists.");
                return TypedResults.Created($"/api/v1/groups/{group.Id}", View(service.Get(group.Id) ?? group, service, storage));
            })
            .WithName("CreateGroup").RequireAuthorization(AdminPolicies.ManageGroups)
            .WithValidationErrors().ProducesProblem(StatusCodes.Status409Conflict);

        groups.MapPut("/{id:int}", async Task<Results<Ok<GroupView>, ProblemHttpResult>> (GroupService service, VirtualFolderService folders,
                StorageMapper storage, IAdminStore admins, CurrentAdmin current, int id, GroupWrite request, CancellationToken ct) =>
                await ReplaceAsync(service, folders, storage, admins, current, id, request, ct))
            .WithName("ReplaceGroup").RequireAuthorization(AdminPolicies.ManageGroups)
            .WithValidationErrors().WithNotFound().ProducesProblem(StatusCodes.Status409Conflict);

        groups.MapPatch("/{id:int}", async Task<Results<Ok<GroupView>, ProblemHttpResult>> (GroupService service, VirtualFolderService folders,
                StorageMapper storage, IAdminStore admins, CurrentAdmin current, IOptions<JsonOptions> json, int id, HttpRequest request,
                CancellationToken ct) =>
            {
                if (service.Get(id) is not { } stored)
                    return NotFound(id);
                var write = MergePatch.Apply(WriteModel(stored, storage), await MergePatch.ReadAsync(request), json.Value.SerializerOptions);
                return await ReplaceAsync(service, folders, storage, admins, current, id, write, ct);
            })
            .WithName("PatchGroup").RequireAuthorization(AdminPolicies.ManageGroups)
            .AcceptsMergePatch<GroupWrite>().WithValidationErrors().WithNotFound();

        groups.MapDelete("/{id:int}", Results<NoContent, ProblemHttpResult> (GroupService service, int id) =>
            {
                if (service.Get(id) == null)
                    return NotFound(id);
                try
                {
                    return service.Remove(id) ? TypedResults.NoContent() : NotFound(id);
                }
                catch (GroupAdministrationException ex)
                {
                    throw new ApiConflictException(ex.Message);
                }
            })
            .WithName("DeleteGroup").WithSummary("Removes a group without members.").RequireAuthorization(AdminPolicies.ManageGroups)
            .WithErrors().WithNotFound().ProducesProblem(StatusCodes.Status409Conflict);

        groups.MapGet("/{id:int}/quotas", Results<Ok<QuotaSettingsModel>, ProblemHttpResult> (GroupService service, int id) =>
                service.Get(id) is { } group ? TypedResults.Ok(new QuotaSettingsModel(group.DiskQuota, group.TransferQuota, group.Bandwidth)) : NotFound(id))
            .WithName("GetGroupQuotas").WithSummary("The quotas and the bandwidth that the group gives its members.").WithErrors().WithNotFound();

        groups.MapPut("/{id:int}/quotas", async Task<Results<Ok<QuotaSettingsModel>, ProblemHttpResult>> (GroupService service, VirtualFolderService folders,
                StorageMapper storage, IAdminStore admins, CurrentAdmin current, int id, QuotaSettingsModel request, CancellationToken ct) =>
            {
                if (service.Get(id) is not { } stored)
                    return NotFound(id);
                var write = WriteModel(stored, storage) with
                {
                    DiskQuota = request.DiskQuota,
                    TransferQuota = request.TransferQuota,
                    Bandwidth = request.Bandwidth,
                };
                await ReplaceAsync(service, folders, storage, admins, current, id, write, ct);
                var saved = service.Get(id)!;
                return TypedResults.Ok(new QuotaSettingsModel(saved.DiskQuota, saved.TransferQuota, saved.Bandwidth));
            })
            .WithName("UpdateGroupQuotas").WithSummary("Sets the quotas and the bandwidth of the group; a value that is not given is not set.")
            .RequireAuthorization(AdminPolicies.ManageGroups).WithValidationErrors().WithNotFound();

        groups.MapGet("/{id:int}/members", Results<Ok<IReadOnlyList<string>>, ProblemHttpResult> (GroupService service, int id) =>
                service.Get(id) == null ? NotFound(id) : TypedResults.Ok(service.MembersOf(id)))
            .WithName("ListGroupMembers").WithSummary("The users (in the scope of the caller) with the group as primary or secondary group.")
            .WithErrors().WithNotFound();

        groups.MapPost("/{id:int}/members", Results<NoContent, ProblemHttpResult> (GroupService service, UserResource users,
                AdminScopedSettingsRepository repository, int id, GroupMemberWrite request) =>
                ChangeMembership(service, users, repository, id, request.Username ?? "", user =>
                {
                    user.SecondaryGroupIds.Remove(id);
                    if (request.Primary)
                    {
                        if (user.PrimaryGroupId is { } old && old != id)
                            user.SecondaryGroupIds.Insert(0, old);
                        user.PrimaryGroupId = id;
                    }
                    else if (user.PrimaryGroupId != id)
                    {
                        user.SecondaryGroupIds.Add(id);
                    }
                }))
            .WithName("AddGroupMember")
            .WithSummary("Adds a user to the group: as its primary group (the old primary group becomes a secondary one), or as a secondary group.")
            .RequireAuthorization(AdminPolicies.ManageUsers).WithValidationErrors().WithNotFound();

        groups.MapDelete("/{id:int}/members/{username}", Results<NoContent, ProblemHttpResult> (GroupService service, UserResource users,
                AdminScopedSettingsRepository repository, int id, string username) =>
                ChangeMembership(service, users, repository, id, username, user =>
                {
                    if (user.PrimaryGroupId == id)
                        user.PrimaryGroupId = null;
                    user.SecondaryGroupIds.Remove(id);
                }))
            .WithName("RemoveGroupMember").RequireAuthorization(AdminPolicies.ManageUsers).WithErrors().WithNotFound();
    }

    private static Results<NoContent, ProblemHttpResult> ChangeMembership(GroupService service, UserResource users,
        AdminScopedSettingsRepository repository, int id, string username, Action<User> change)
    {
        if (service.Get(id) == null)
            return NotFound(id);
        if (users.Get(username) is not { } user)
            return ApiResults.NotFound($"The user '{username}' does not exist.");
        user.SecondaryGroupIds ??= [];
        change(user);
        var problems = service.ValidateMembership(user);
        if (problems.Count > 0)
            throw new ApiValidationException(new Dictionary<string, string[]> { ["groups"] = problems.ToArray() });
        return repository.UpdateUser(user) ? TypedResults.NoContent() : ApiResults.NotFound($"The user '{username}' does not exist.");
    }

    private static async Task<Results<Ok<GroupView>, ProblemHttpResult>> ReplaceAsync(GroupService service, VirtualFolderService folders,
        StorageMapper storage, IAdminStore admins, CurrentAdmin current, int id, GroupWrite request, CancellationToken ct)
    {
        if (service.Get(id) is not { } stored)
            return NotFound(id);
        var group = await BuildAsync(request, stored.Clone(), folders, storage, admins, current, ct);
        if (!service.TryUpdate(group))
            throw new ApiConflictException($"Another group has the name '{group.Name}'.");
        return TypedResults.Ok(View(service.Get(id) ?? group, service, storage));
    }

    /// <summary>Writes the request to the group after the rules of the Groups page, or throws with every problem.</summary>
    private static async Task<Group> BuildAsync(GroupWrite request, Group group, VirtualFolderService folders, StorageMapper storage,
        IAdminStore admins, CurrentAdmin current, CancellationToken ct)
    {
        var errors = new ValidationErrors();
        group.Name = request.Name?.Trim() ?? "";
        group.Description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim();
        group.Permissions = PermissionModels.Parse(request.Permissions, errors);
        group.PathFilters = PermissionModels.ParseFilters(request.PathFilters);
        group.Storage = storage.Build(request.Storage, group.Id == 0 ? null : group.Storage, errors, "storage");
        group.VirtualFolders = PermissionModels.Mounts(request.VirtualFolders);
        QuotaModels.Validate(errors, request.DiskQuota, request.TransferQuota, request.Bandwidth, group.VirtualFolders);
        (group.DiskQuota, group.TransferQuota, group.Bandwidth) = QuotaModels.Normalize(request.DiskQuota, request.TransferQuota, request.Bandwidth);
        errors.AddRange("virtualFolders", folders.ValidateMounts(group.VirtualFolders));
        if (request.AllowedAuthMethods != null)
        {
            var unknown = new List<string>();
            group.AllowedAuthMethods = AuthMethodNames.Parse(request.AllowedAuthMethods, unknown);
            errors.AddRange("allowedAuthMethods", unknown.Select(n => $"'{n}' is not a login method (password, publickey, keyboard-interactive)."));
        }
        else
        {
            group.AllowedAuthMethods = null;
        }
        var ips = (request.AllowedIps ?? []).Where(e => !string.IsNullOrWhiteSpace(e)).Select(e => e.Trim()).ToList();
        group.AllowedIps = ips.Count == 0 ? null : ips;
        errors.AddRange("", GroupService.Validate(group));
        if (current.Actor.ScopeRoleId == null)
        {
            group.RoleId = request.RoleId;
            if (request.RoleId is { } roleId && await admins.GetRoleAsync(roleId, ct) == null)
                errors.Add("roleId", "The role does not exist.");
        }
        else if (group.Id == 0)
        {
            group.RoleId = request.RoleId;
        }
        errors.ThrowIfAny();
        return group;
    }

    private static GroupWrite WriteModel(Group group, StorageMapper storage) => new()
    {
        Name = group.Name,
        Description = group.Description,
        Permissions = PermissionModels.Names(group.Permissions),
        PathFilters = PermissionModels.Models(group.PathFilters),
        Storage = storage.WriteModel(group.Storage),
        VirtualFolders = group.VirtualFolders.Select(VirtualFolderMountModel.From).ToList(),
        AllowedAuthMethods = group.AllowedAuthMethods is { } methods ? AuthMethodNames.Of(methods).ToList() : null,
        AllowedIps = group.AllowedIps?.ToList(),
        RoleId = group.RoleId,
        DiskQuota = group.DiskQuota,
        TransferQuota = group.TransferQuota,
        Bandwidth = group.Bandwidth,
    };

    private static GroupView View(Group group, GroupService service, StorageMapper storage) => new(group.Id, group.Name, group.Description,
        group.Permissions?.ToDictionary(p => p.Key, p => FlagNames.Of(p.Value), StringComparer.Ordinal),
        group.PathFilters?.ToDictionary(p => p.Key, p => PathFilterModel.From(p.Value), StringComparer.Ordinal),
        storage.View(group.Storage),
        group.VirtualFolders.Select(VirtualFolderMountModel.From).ToList(),
        group.AllowedAuthMethods is { } methods ? AuthMethodNames.Of(methods) : null,
        group.AllowedIps?.ToList(), group.RoleId, group.DiskQuota, group.TransferQuota, group.Bandwidth, service.MembersOf(group.Id));

    private static ProblemHttpResult NotFound(int id) => ApiResults.NotFound($"The group {id} does not exist.");
}
