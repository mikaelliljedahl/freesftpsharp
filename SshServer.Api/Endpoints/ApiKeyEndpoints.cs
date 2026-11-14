using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using SshServer.Administration;
using SshServer.Api.ApiKeys;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;

namespace SshServer.Api.Endpoints;

/// <summary>An API key to create: a name, an optional expiry (UTC), and optional scopes (admin permissions) that narrow it.</summary>
public sealed record ApiKeyCreate(string? Name, DateTime? ExpiresAt, List<string>? Scopes);

/// <summary>/api/v1/api-keys: the API keys of the caller (see <see cref="ApiKeyService"/> for the rules).</summary>
internal static class ApiKeyEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        var keys = api.MapGroup("/api-keys").WithTags("API keys");

        keys.MapGet("/", async (ApiKeyService service, CurrentAdmin current, bool? all, CancellationToken ct) =>
                TypedResults.Ok(await service.ListAsync(current.Actor, all == true, ct)))
            .WithName("ListApiKeys").WithSummary("Lists the API keys of the caller; ?all=true lists those of every administrator it manages (ManageAdmins).")
            .WithErrors();

        keys.MapPost("/", async (ApiKeyService service, CurrentAdmin current, ApiKeyCreate request, CancellationToken ct) =>
            {
                AdminPermissions? scopes = null;
                if (request.Scopes != null)
                {
                    var unknown = new List<string>();
                    scopes = FlagNames.Parse<AdminPermissions>(request.Scopes, unknown);
                    if (unknown.Count > 0)
                        throw new ApiValidationException("scopes", $"Not an admin permission: {string.Join(", ", unknown)}.");
                }
                var created = await service.CreateAsync(current.Actor, request.Name, request.ExpiresAt, scopes, ct);
                return TypedResults.Created($"/api/v1/api-keys/{created.ApiKey.Id}", created);
            })
            .WithName("CreateApiKey").WithSummary("Creates an API key for the caller. The key is in the answer only, once. Needs a bearer token.")
            .WithValidationErrors();

        keys.MapDelete("/{id:int}", async Task<Results<NoContent, ProblemHttpResult>> (ApiKeyService service, CurrentAdmin current, int id, CancellationToken ct) =>
                await service.RevokeAsync(current.Actor, id, ct) ? TypedResults.NoContent() : ApiResults.NotFound($"The API key {id} does not exist."))
            .WithName("RevokeApiKey").WithSummary("Revokes an API key. Needs a bearer token.").WithErrors().WithNotFound();
    }
}
