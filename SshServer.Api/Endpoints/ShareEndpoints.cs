using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using SshServer.Administration;

namespace SshServer.Api.Endpoints;

/// <summary>
/// /api/v1/shares (#70): the share links of the users, over the scoped service of the admin page Shares
/// (<see cref="ScopedShares"/>: ManageUsers; a scoped administrator sees only the shares of its users). The password hash
/// is never in the answer. The users create their shares in the web client.
/// </summary>
internal static class ShareEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        var shares = api.MapGroup("/shares").WithTags("Shares").RequireAuthorization(AdminPolicies.ManageUsers);

        shares.MapGet("/", async (ScopedShares service, string? username, int? offset, int? limit, CancellationToken ct) =>
                TypedResults.Ok(Paging.Of(await service.ListAsync(string.IsNullOrWhiteSpace(username) ? null : username.Trim(), ct), offset, limit, s => s)))
            .WithName("ListShares").WithSummary("The share links of the users, newest first; ?username= for one user.").WithValidationErrors();

        shares.MapDelete("/{id}", async Task<Results<NoContent, ProblemHttpResult>> (ScopedShares service, string id, CancellationToken ct) =>
                await service.RevokeAsync(id, ct) ? TypedResults.NoContent() : ApiResults.NotFound($"The share {id} does not exist."))
            .WithName("RevokeShare").WithSummary("Revokes a share link: it stops working at once.").WithErrors().WithNotFound();
    }
}
