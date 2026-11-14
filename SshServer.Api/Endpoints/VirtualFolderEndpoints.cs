using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using JsonOptions = Microsoft.AspNetCore.Http.Json.JsonOptions;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using SshServer.Administration;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace SshServer.Api.Endpoints;

/// <summary>A virtual folder (#56) in the API, with the users (in the scope of the caller) that mount it.</summary>
public sealed record VirtualFolderView(int Id, string Name, string? Description, StorageView? Storage, IReadOnlyList<string> Users);

/// <summary>A virtual folder to create or save. The storage needs a provider; its secrets are write-only.</summary>
public sealed record VirtualFolderWrite
{
    public string? Name { get; init; }

    public string? Description { get; init; }

    public StorageWrite? Storage { get; init; }
}

/// <summary>
/// /api/v1/virtual-folders and /api/v1/storage-providers, over <see cref="VirtualFolderService"/> of the admin UI: an
/// administrator who manages users or folders reads them, one with <see cref="AdminPermissions.ManageFolders"/> changes them.
/// </summary>
internal static class VirtualFolderEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        var providers = api.MapGroup("/storage-providers").WithTags("Storage");
        providers.MapGet("/", (StorageMapper storage) => TypedResults.Ok(storage.Providers()))
            .WithName("ListStorageProviders").WithSummary("The registered storage providers and their options.").WithErrors();
        providers.MapPost("/test", async (StorageMapper storage, CurrentAdmin current, StorageWrite request, CancellationToken ct) =>
            {
                if (!current.Has(AdminPermissions.ManageUsers) && !current.Has(AdminPermissions.ManageFolders))
                    throw new AdminAccessDeniedException("This needs the permission ManageUsers or ManageFolders.");
                return TypedResults.Ok(await storage.TestAsync(request, null, ct));
            })
            .WithName("TestStorage").WithSummary("Creates the storage (not saved) and lists its root.").WithValidationErrors();

        var folders = api.MapGroup("/virtual-folders").WithTags("Virtual folders");

        folders.MapGet("/", (VirtualFolderService service, StorageMapper storage, int? offset, int? limit) =>
                TypedResults.Ok(Paging.Of(service.List(), offset, limit, f => View(f, service, storage))))
            .WithName("ListVirtualFolders").WithSummary("Lists the virtual folders (needs ManageFolders or ManageUsers).").WithValidationErrors();

        folders.MapGet("/{id:int}", Results<Ok<VirtualFolderView>, ProblemHttpResult> (VirtualFolderService service, StorageMapper storage, int id) =>
                service.Get(id) is { } folder ? TypedResults.Ok(View(folder, service, storage)) : NotFound(id))
            .WithName("GetVirtualFolder").WithErrors().WithNotFound();

        folders.MapPost("/", (VirtualFolderService service, StorageMapper storage, VirtualFolderWrite request) =>
            {
                var folder = Build(request, new VirtualFolder(), storage);
                if (!service.TryAdd(folder))
                    throw new ApiConflictException($"A virtual folder with the name '{folder.Name}' already exists.");
                return TypedResults.Created($"/api/v1/virtual-folders/{folder.Id}", View(service.Get(folder.Id) ?? folder, service, storage));
            })
            .WithName("CreateVirtualFolder").RequireAuthorization(AdminPolicies.ManageFolders)
            .WithValidationErrors().ProducesProblem(StatusCodes.Status409Conflict);

        folders.MapPut("/{id:int}", Results<Ok<VirtualFolderView>, ProblemHttpResult> (VirtualFolderService service, StorageMapper storage, int id,
                VirtualFolderWrite request) => Replace(service, storage, id, request))
            .WithName("ReplaceVirtualFolder").RequireAuthorization(AdminPolicies.ManageFolders)
            .WithValidationErrors().WithNotFound().ProducesProblem(StatusCodes.Status409Conflict);

        folders.MapPatch("/{id:int}", async Task<Results<Ok<VirtualFolderView>, ProblemHttpResult>> (VirtualFolderService service, StorageMapper storage,
                IOptions<JsonOptions> json, int id, HttpRequest request) =>
            {
                if (service.Get(id) is not { } stored)
                    return NotFound(id);
                var current = new VirtualFolderWrite { Name = stored.Name, Description = stored.Description, Storage = storage.WriteModel(stored.Storage) };
                return Replace(service, storage, id, MergePatch.Apply(current, await MergePatch.ReadAsync(request), json.Value.SerializerOptions));
            })
            .WithName("PatchVirtualFolder").RequireAuthorization(AdminPolicies.ManageFolders)
            .AcceptsMergePatch<VirtualFolderWrite>().WithValidationErrors().WithNotFound();

        folders.MapDelete("/{id:int}", Results<NoContent, ProblemHttpResult> (VirtualFolderService service, int id) =>
                service.Remove(id) ? TypedResults.NoContent() : NotFound(id))
            .WithName("DeleteVirtualFolder").WithSummary("Removes a folder and unmounts it from every user. The data in its storage stays.")
            .RequireAuthorization(AdminPolicies.ManageFolders).WithErrors().WithNotFound();
    }

    private static Results<Ok<VirtualFolderView>, ProblemHttpResult> Replace(VirtualFolderService service, StorageMapper storage, int id, VirtualFolderWrite request)
    {
        if (service.Get(id) is not { } stored)
            return NotFound(id);
        var folder = Build(request, new VirtualFolder { Id = id, Storage = stored.Storage }, storage);
        if (!service.TryUpdate(folder))
            throw new ApiConflictException($"Another virtual folder has the name '{folder.Name}'.");
        return TypedResults.Ok(View(service.Get(id) ?? folder, service, storage));
    }

    private static VirtualFolder Build(VirtualFolderWrite request, VirtualFolder folder, StorageMapper storage)
    {
        var errors = new ValidationErrors();
        errors.Add("name", VirtualFolderService.ValidateName(request.Name));
        var config = storage.Build(request.Storage, folder.Id == 0 ? null : folder.Storage, errors, "storage");
        if (string.IsNullOrWhiteSpace(request.Storage?.Provider))
            errors.Add("storage.provider", "Select a storage provider.");
        errors.ThrowIfAny();
        folder.Name = request.Name!.Trim();
        folder.Description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim();
        folder.Storage = config!;
        return folder;
    }

    private static VirtualFolderView View(VirtualFolder folder, VirtualFolderService service, StorageMapper storage) =>
        new(folder.Id, folder.Name, folder.Description, storage.View(folder.Storage), service.UsersOf(folder.Id));

    private static ProblemHttpResult NotFound(int id) => ApiResults.NotFound($"The virtual folder {id} does not exist.");
}
