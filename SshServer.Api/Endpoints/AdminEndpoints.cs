using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using JsonOptions = Microsoft.AspNetCore.Http.Json.JsonOptions;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using SshServer.Administration;
using SshServer.Interfaces.Admins;

namespace SshServer.Api.Endpoints;

/// <summary>An administrator in the API, without its password hash.</summary>
public sealed record AdminView(string Username, string? Email, AdminStatus Status, IReadOnlyList<string> Permissions,
    IReadOnlyList<string> AllowedIps, int? ScopeRoleId, DateTime? LastLoginAt, bool MustChangePassword)
{
    public static AdminView From(Admin admin) => new(admin.Username, admin.Email, admin.Status, PermissionNames.Of(admin.Permissions),
        admin.AllowedIps?.ToList() ?? [], admin.ScopeRoleId, admin.LastLoginAt, admin.MustChangePassword);
}

/// <summary>An administrator to create or save. The password is write-only: on a save without it the stored one stays.</summary>
public sealed record AdminWrite
{
    public string? Username { get; init; }

    public string? Password { get; init; }

    public string? Email { get; init; }

    public AdminStatus? Status { get; init; }

    /// <summary>The permissions, for example ["ManageUsers","ViewAudit"] or ["SuperAdmin"].</summary>
    public List<string>? Permissions { get; init; }

    public List<string>? AllowedIps { get; init; }

    public int? ScopeRoleId { get; init; }

    public bool? MustChangePassword { get; init; }

    public static AdminWrite From(Admin admin) => new()
    {
        Username = admin.Username,
        Email = admin.Email,
        Status = admin.Status,
        Permissions = PermissionNames.Of(admin.Permissions).ToList(),
        AllowedIps = admin.AllowedIps?.ToList() ?? [],
        ScopeRoleId = admin.ScopeRoleId,
        MustChangePassword = admin.MustChangePassword,
    };

    public AdminInput ToInput(string username)
    {
        var unknown = new List<string>();
        var permissions = FlagNames.Parse<AdminPermissions>(Permissions, unknown);
        if (unknown.Count > 0)
            throw new ApiValidationException("permissions", $"Not an admin permission: {string.Join(", ", unknown)}.");
        return new AdminInput(username)
        {
            Email = Email,
            Status = Status ?? AdminStatus.Enabled,
            Permissions = permissions,
            AllowedIps = AllowedIps ?? [],
            ScopeRoleId = ScopeRoleId,
            MustChangePassword = MustChangePassword ?? false,
        };
    }
}

/// <summary>A scope role (#60) in the API.</summary>
public sealed record RoleView(int Id, string Name, string? Description)
{
    public static RoleView From(Role role) => new(role.Id, role.Name, role.Description);
}

public sealed record RoleWrite(string? Name, string? Description);

/// <summary>
/// /api/v1/admins and /api/v1/roles over <see cref="AdminAdministrationService"/>, the service of the Admins and Roles
/// pages: it needs <see cref="AdminPermissions.ManageAdmins"/> and never lets an administrator grant more than it has.
/// </summary>
internal static class AdminEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        var admins = api.MapGroup("/admins").WithTags("Administrators").RequireAuthorization(AdminPolicies.ManageAdmins);

        admins.MapGet("/", async (AdminAdministrationService service, CurrentAdmin current, int? offset, int? limit, CancellationToken ct) =>
                TypedResults.Ok(Paging.Of(await service.ListAdminsAsync(current.Actor, ct), offset, limit, AdminView.From)))
            .WithName("ListAdmins").WithValidationErrors();

        admins.MapGet("/{username}", async Task<Results<Ok<AdminView>, ProblemHttpResult>> (AdminAdministrationService service, CurrentAdmin current,
                string username, CancellationToken ct) =>
                await FindAsync(service, current, username, ct) is { } admin ? TypedResults.Ok(AdminView.From(admin)) : NotFound(username))
            .WithName("GetAdmin").WithErrors().WithNotFound();

        admins.MapPost("/", async (AdminAdministrationService service, CurrentAdmin current, AdminWrite request, CancellationToken ct) =>
            {
                var admin = await service.CreateAdminAsync(current.Actor, request.ToInput(request.Username ?? ""), request.Password ?? "", ct);
                return TypedResults.Created($"/api/v1/admins/{Uri.EscapeDataString(admin.Username)}", AdminView.From(admin));
            })
            .WithName("CreateAdmin").WithValidationErrors();

        admins.MapPut("/{username}", async Task<Results<Ok<AdminView>, ProblemHttpResult>> (AdminAdministrationService service, CurrentAdmin current,
                string username, AdminWrite request, CancellationToken ct) => await ReplaceAsync(service, current, username, request, ct))
            .WithName("ReplaceAdmin").WithValidationErrors().WithNotFound();

        admins.MapPatch("/{username}", async Task<Results<Ok<AdminView>, ProblemHttpResult>> (AdminAdministrationService service, CurrentAdmin current,
                IOptions<JsonOptions> json, string username, HttpRequest request, CancellationToken ct) =>
            {
                if (await FindAsync(service, current, username, ct) is not { } stored)
                    return NotFound(username);
                return await ReplaceAsync(service, current, username, MergePatch.Apply(AdminWrite.From(stored), await MergePatch.ReadAsync(request), json.Value.SerializerOptions), ct);
            })
            .WithName("PatchAdmin").AcceptsMergePatch<AdminWrite>().WithValidationErrors().WithNotFound();

        admins.MapDelete("/{username}", async Task<Results<NoContent, ProblemHttpResult>> (AdminAdministrationService service, CurrentAdmin current,
                string username, CancellationToken ct) =>
            {
                if (await FindAsync(service, current, username, ct) == null)
                    return NotFound(username);
                await service.DeleteAdminAsync(current.Actor, username, ct);
                return TypedResults.NoContent();
            })
            .WithName("DeleteAdmin").WithErrors().WithNotFound();

        var roles = api.MapGroup("/roles").WithTags("Roles").RequireAuthorization(AdminPolicies.ManageAdmins);

        roles.MapGet("/", async (AdminAdministrationService service, CurrentAdmin current, int? offset, int? limit, CancellationToken ct) =>
                TypedResults.Ok(Paging.Of(await service.ListRolesAsync(current.Actor, ct), offset, limit, RoleView.From)))
            .WithName("ListRoles").WithValidationErrors();

        roles.MapGet("/{id:int}", async Task<Results<Ok<RoleView>, ProblemHttpResult>> (AdminAdministrationService service, CurrentAdmin current,
                int id, CancellationToken ct) =>
                (await service.ListRolesAsync(current.Actor, ct)).FirstOrDefault(r => r.Id == id) is { } role
                    ? TypedResults.Ok(RoleView.From(role))
                    : RoleNotFound(id))
            .WithName("GetRole").WithErrors().WithNotFound();

        roles.MapPost("/", async (AdminAdministrationService service, CurrentAdmin current, RoleWrite request, CancellationToken ct) =>
            {
                var role = await service.CreateRoleAsync(current.Actor, request.Name ?? "", request.Description, ct);
                return TypedResults.Created($"/api/v1/roles/{role.Id}", RoleView.From(role));
            })
            .WithName("CreateRole").WithValidationErrors();

        roles.MapPut("/{id:int}", async Task<Results<Ok<RoleView>, ProblemHttpResult>> (AdminAdministrationService service, CurrentAdmin current,
                int id, RoleWrite request, CancellationToken ct) =>
            {
                if ((await service.ListRolesAsync(current.Actor, ct)).All(r => r.Id != id))
                    return RoleNotFound(id);
                var role = await service.UpdateRoleAsync(current.Actor, new Role { Id = id, Name = request.Name ?? "", Description = request.Description }, ct);
                return TypedResults.Ok(RoleView.From(role));
            })
            .WithName("ReplaceRole").WithValidationErrors().WithNotFound();

        roles.MapDelete("/{id:int}", async Task<Results<NoContent, ProblemHttpResult>> (AdminAdministrationService service, CurrentAdmin current,
                int id, CancellationToken ct) =>
            {
                if ((await service.ListRolesAsync(current.Actor, ct)).All(r => r.Id != id))
                    return RoleNotFound(id);
                await service.DeleteRoleAsync(current.Actor, id, ct);
                return TypedResults.NoContent();
            })
            .WithName("DeleteRole").WithSummary("Removes a role that no user and no administrator has.").WithValidationErrors().WithNotFound();
    }

    private static async Task<Results<Ok<AdminView>, ProblemHttpResult>> ReplaceAsync(AdminAdministrationService service, CurrentAdmin current,
        string username, AdminWrite request, CancellationToken ct)
    {
        var stored = await FindAsync(service, current, username, ct);
        if (stored == null)
            return NotFound(username);
        if (request.Username != null && !string.Equals(request.Username.Trim(), stored.Username, StringComparison.OrdinalIgnoreCase))
            throw new ApiValidationException("username", "The user name of an administrator cannot change.");
        var admin = await service.UpdateAdminAsync(current.Actor, request.ToInput(stored.Username), request.Password, ct);
        return TypedResults.Ok(AdminView.From(admin));
    }

    private static async Task<Admin?> FindAsync(AdminAdministrationService service, CurrentAdmin current, string username, CancellationToken ct) =>
        (await service.ListAdminsAsync(current.Actor, ct)).FirstOrDefault(a => string.Equals(a.Username, username, StringComparison.OrdinalIgnoreCase));

    private static ProblemHttpResult NotFound(string username) => ApiResults.NotFound($"The administrator '{username}' does not exist.");

    private static ProblemHttpResult RoleNotFound(int id) => ApiResults.NotFound($"The role {id} does not exist.");
}
