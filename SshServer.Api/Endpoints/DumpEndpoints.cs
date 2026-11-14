using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using SshServer.Administration;
using SshServer.Api.Dump;

namespace SshServer.Api.Endpoints;

/// <summary>/api/v1/dump and /api/v1/load (SuperAdmin): see <see cref="DumpService"/>.</summary>
internal static class DumpEndpoints
{
    /// <summary>The header with the passphrase of the secrets in a dump. Without it a dump has no secrets.</summary>
    public const string PassphraseHeader = "X-Dump-Passphrase";

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/dump", async (DumpService service, [FromHeader(Name = PassphraseHeader)] string? passphrase, CancellationToken ct) =>
                TypedResults.Ok(await service.DumpAsync(passphrase, ct)))
            .WithTags("Backup").WithName("Dump")
            .WithSummary($"Exports every stored object. The storage and webhook secrets are in it only with a passphrase ({PassphraseHeader}), encrypted with it.")
            .RequireAuthorization(AdminPolicies.SuperAdmin).WithValidationErrors();

        api.MapPost("/load", async (DumpService service, DumpDocument dump, [FromHeader(Name = PassphraseHeader)] string? passphrase,
                string? mode, CancellationToken ct) =>
            {
                var loadMode = LoadMode.Add;
                if (mode != null && (!Enum.TryParse(mode, ignoreCase: true, out loadMode) || !Enum.IsDefined(loadMode) || int.TryParse(mode, out _)))
                    throw new ApiValidationException("mode", "The mode is add, update or skip.");
                return TypedResults.Ok(await service.LoadAsync(dump, loadMode, passphrase, ct));
            })
            .WithTags("Backup").WithName("Load")
            .WithSummary("Imports a dump. ?mode=add (default: an existing object is an error), update (replace existing objects) or skip.")
            .RequireAuthorization(AdminPolicies.SuperAdmin).WithValidationErrors();
    }
}
