using FxSsh.SshServerModule;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using JsonOptions = Microsoft.AspNetCore.Http.Json.JsonOptions;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using SshServer.Administration;
using SshServer.Interfaces.Authentication;
using Microsoft.Extensions.Logging;
using FxSsh.SshServerModule.Security;
using SshServer.Interfaces.Users;
using SshServer.TwoFactor;
using SshServerModule.Quotas;

namespace SshServer.Api.Endpoints;

/// <summary>/api/v1/users: the SFTP users, their public keys, and the storage providers for their storage.</summary>
internal static class UserEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        var users = api.MapGroup("/users").WithTags("Users").RequireAuthorization(AdminPolicies.ManageUsers);

        users.MapGet("/", (UserResource resource, string? search, int? roleId, int? offset, int? limit) =>
                TypedResults.Ok(Paging.Of(resource.List(search, roleId), offset, limit, u => UserView.From(u, resource.Storage))))
            .WithName("ListUsers").WithSummary("Lists the users (in the scope of the caller), by name.").WithValidationErrors();

        users.MapGet("/{username}", Results<Ok<UserView>, ProblemHttpResult> (UserResource resource, string username) =>
                resource.Get(username) is { } user ? TypedResults.Ok(UserView.From(user, resource.Storage)) : NotFound(username))
            .WithName("GetUser").WithErrors().WithNotFound();

        users.MapPost("/", async (UserResource resource, UserWrite user, CancellationToken ct) =>
            {
                var created = await resource.CreateAsync(user, ct);
                return TypedResults.Created($"/api/v1/users/{Uri.EscapeDataString(created.Username)}", UserView.From(created, resource.Storage));
            })
            .WithName("CreateUser").WithValidationErrors().ProducesProblem(StatusCodes.Status409Conflict);

        users.MapPut("/{username}", async Task<Results<Ok<UserView>, ProblemHttpResult>> (UserResource resource, string username, UserWrite user, CancellationToken ct) =>
                await resource.ReplaceAsync(username, user, ct) is { } saved ? TypedResults.Ok(UserView.From(saved, resource.Storage)) : NotFound(username))
            .WithName("ReplaceUser").WithSummary("Saves a user. Values that are not given get their defaults; the password stays unless one is given.")
            .WithValidationErrors().WithNotFound();

        users.MapPatch("/{username}", async Task<Results<Ok<UserView>, ProblemHttpResult>> (UserResource resource, IOptions<JsonOptions> json,
                string username, HttpRequest request, CancellationToken ct) =>
            {
                if (resource.Get(username) is not { } stored)
                    return NotFound(username);
                var write = MergePatch.Apply(UserWrite.From(stored, resource.Storage), await MergePatch.ReadAsync(request), json.Value.SerializerOptions);
                return await resource.ReplaceAsync(username, write, ct) is { } saved ? TypedResults.Ok(UserView.From(saved, resource.Storage)) : NotFound(username);
            })
            .WithName("PatchUser").WithSummary("Changes some values of a user (JSON merge patch, RFC 7396).")
            .AcceptsMergePatch<UserWrite>().WithValidationErrors().WithNotFound();

        users.MapDelete("/{username}", Results<NoContent, ProblemHttpResult> (UserResource resource, UserAdministrationService service, string username) =>
                resource.Get(username) != null && service.Remove(username) ? TypedResults.NoContent() : NotFound(username))
            .WithName("DeleteUser").WithSummary("Removes a user. The files in its storage stay.").WithErrors().WithNotFound();

        MapPublicKeys(users);
        MapQuotas(users);
        MapAppPasswords(users);
        MapTwoFactor(users);
    }

    private static void MapAppPasswords(RouteGroupBuilder users)
    {
        users.MapGet("/{username}/app-passwords", Results<Ok<List<AppPasswordView>>, ProblemHttpResult> (UserResource resource, TimeProvider time,
                string username) =>
                resource.Get(username) is { } user
                    ? TypedResults.Ok((user.AppPasswords ?? []).Select(a => AppPasswordView.From(a, time.GetUtcNow().UtcDateTime)).ToList())
                    : NotFound(username))
            .WithName("ListUserAppPasswords").WithSummary("The app passwords of the user: the metadata only, never the secret.")
            .WithErrors().WithNotFound();

        // An app password is allowed for a user of an external provider too (#64), as in the Users page: it is a separate secret of this server.
        users.MapPost("/{username}/app-passwords", Results<Created<AppPasswordCreated>, ProblemHttpResult> (UserResource resource,
                UserAdministrationService service, TimeProvider time, ILoggerFactory logs, HttpContext http, string username, AppPasswordCreate request) =>
            {
                if (resource.Get(username) is not { } user)
                    return NotFound(username);
                var unknown = new List<string>();
                var protocols = request.Protocols == null ? UserProtocols.WebDav : ProtocolNames.Parse(request.Protocols, unknown);
                if (unknown.Count > 0)
                    throw new ApiValidationException("protocols", $"'{string.Join("', '", unknown)}' is not a protocol ({ProtocolNames.Allowed}).");
                var now = time.GetUtcNow().UtcDateTime;
                var (entry, secret) = service.CreateAppPassword(user.Username, request.Name, protocols, ApiTime.ToUtc(request.ExpiresAt), now);
                logs.CreateLogger("SshServer.Api.AppPasswords").LogInformation("REST API: the app password {Name} ({Id}) of the user {Username} was created.",
                    LogText.Clean(entry.Name), entry.Id, LogText.Clean(user.Username));
                http.Response.Headers.CacheControl = "no-store"; // the secret is in this response only
                return TypedResults.Created($"/api/v1/users/{Uri.EscapeDataString(user.Username)}/app-passwords", new AppPasswordCreated(AppPasswordView.From(entry, now), secret));
            })
            .WithName("CreateUserAppPassword").WithSummary("Creates an app password and returns its secret once; it is not stored and cannot be read again.")
            .WithValidationErrors().WithNotFound();

        users.MapDelete("/{username}/app-passwords/{id}", Results<NoContent, ProblemHttpResult> (UserResource resource, UserAdministrationService service,
                ILoggerFactory logs, string username, string id) =>
            {
                if (resource.Get(username) is not { } user || !service.RemoveAppPassword(user.Username, id))
                    return ApiResults.NotFound($"The user '{username}' has no app password '{id}'.");
                logs.CreateLogger("SshServer.Api.AppPasswords").LogInformation("REST API: the app password {Id} of the user {Username} was revoked.",
                    LogText.Clean(id), LogText.Clean(user.Username));
                return TypedResults.NoContent();
            })
            .WithName("RevokeUserAppPassword").WithSummary("Revokes an app password: it stops working at once.").WithErrors().WithNotFound();
    }

    private static void MapTwoFactor(RouteGroupBuilder users)
    {
        users.MapGet("/{username}/two-factor", async Task<Results<Ok<TwoFactorView>, ProblemHttpResult>> (UserResource resource,
                TwoFactorAdministration twoFactor, string username, CancellationToken ct) =>
                resource.Get(username) is { } user
                    ? TypedResults.Ok(TwoFactorView.From(await twoFactor.GetStatusAsync(TwoFactorTarget.User(user.Username), ct)))
                    : NotFound(username))
            .WithName("GetUserTwoFactor").WithSummary("Whether the user has a TOTP second factor, and when it was set up. Never the secret.")
            .WithErrors().WithNotFound();

        users.MapDelete("/{username}/two-factor", async Task<Results<NoContent, ProblemHttpResult>> (UserResource resource,
                TwoFactorAdministration twoFactor, ILoggerFactory logs, string username, CancellationToken ct) =>
            {
                if (resource.Get(username) is not { } user)
                    return NotFound(username);
                if (!await twoFactor.ResetAsync(TwoFactorTarget.User(user.Username), "", ct))
                    return ApiResults.NotFound($"The user '{username}' has no second factor.");
                logs.CreateLogger("SshServer.Api.TwoFactor").LogInformation("REST API: the second factor of the user {Username} was reset.", LogText.Clean(user.Username));
                return TypedResults.NoContent();
            })
            .WithName("ResetUserTwoFactor").WithSummary("Resets the second factor of the user: the next login needs no code, and the user can set it up again.")
            .WithErrors().WithNotFound();
    }

    private static void MapPublicKeys(RouteGroupBuilder users)
    {
        users.MapGet("/{username}/public-keys", Results<Ok<List<PublicKeyView>>, ProblemHttpResult> (UserResource resource, string username) =>
                resource.Get(username) is { } user
                    ? TypedResults.Ok((user.PublicKeys ?? []).Select(PublicKeyView.From).ToList())
                    : NotFound(username))
            .WithName("ListUserPublicKeys").WithErrors().WithNotFound();

        users.MapPost("/{username}/public-keys", Results<Ok<PublicKeysAdded>, ProblemHttpResult> (UserResource resource, UserAdministrationService service,
                string username, PublicKeysAdd request) =>
            {
                if (resource.Get(username) == null)
                    return NotFound(username);
                var expires = ApiTime.ToUtc(request.ExpiresAt);
                var (added, skipped) = service.AddPublicKeys(username, request.Keys ?? "", expires);
                return TypedResults.Ok(new PublicKeysAdded(added, skipped));
            })
            .WithName("AddUserPublicKeys").WithSummary("Adds keys (an authorized_keys text). A key that the user has already is skipped.")
            .WithValidationErrors().WithNotFound();

        users.MapPost("/{username}/public-keys/generate", async Task<Results<Ok<GeneratedKey>, ProblemHttpResult>> (UserResource resource,
                UserAdministrationService service, string username, GenerateKeyRequest request) =>
            {
                if (resource.Get(username) is not { } user)
                    return NotFound(username);
                var type = (request.Type ?? "ed25519").Trim().ToLowerInvariant();
                if (type is not ("ed25519" or "rsa"))
                    throw new ApiValidationException("type", "The key type is ed25519 or rsa.");
                var comment = $"{user.Username}@freesftpsharp";
                var key = await Task.Run(() => type == "ed25519"
                    ? UserKeyGenerator.GenerateEd25519(comment, DateTime.UtcNow)
                    : UserKeyGenerator.GenerateRsa(comment, DateTime.UtcNow));
                service.AddPublicKey(user.Username, key.PublicKey);
                var fileName = (type == "ed25519" ? $"{user.Username}_ed25519" : user.Username) + key.FileExtension;
                return TypedResults.Ok(new GeneratedKey(PublicKeyView.From(key.PublicKey), key.PrivateKey, fileName));
            })
            .WithName("GenerateUserKey").WithSummary("Generates a key pair, adds the public key, and returns the private key once (it is not stored).")
            .WithValidationErrors().WithNotFound();

        users.MapDelete("/{username}/public-keys", Results<NoContent, ProblemHttpResult> (UserResource resource, UserAdministrationService service,
                string username, string fingerprint) =>
            {
                var key = resource.Get(username)?.PublicKeys?.FirstOrDefault(k => string.Equals(k.Fingerprint, fingerprint, StringComparison.Ordinal));
                if (key == null)
                    return ApiResults.NotFound($"The user '{username}' has no key {fingerprint}.");
                service.RemovePublicKey(username, key.KeyBase64);
                return TypedResults.NoContent();
            })
            .WithName("RemoveUserPublicKey").WithSummary("Removes the key with this fingerprint (?fingerprint=SHA256:...).")
            .WithErrors().WithNotFound();
    }

    private static void MapQuotas(RouteGroupBuilder users)
    {
        users.MapGet("/{username}/quotas", async Task<Results<Ok<UserQuotasView>, ProblemHttpResult>> (UserResource resource,
                QuotaAdministrationService quotas, string username, CancellationToken ct) =>
            {
                if (resource.Get(username) is not { } user || await quotas.GetAsync(username, ct) is not { } usage)
                    return NotFound(username);
                return TypedResults.Ok(new UserQuotasView(new QuotaSettingsModel(user.DiskQuota, user.TransferQuota, user.Bandwidth), usage));
            })
            .WithName("GetUserQuotas").WithSummary("The own quotas of the user, and the effective limits (also from its groups) with their usage.")
            .WithErrors().WithNotFound();

        users.MapPut("/{username}/quotas", async Task<Results<Ok<QuotaSettingsModel>, ProblemHttpResult>> (UserResource resource,
                IOptions<JsonOptions> json, string username, QuotaSettingsModel request, CancellationToken ct) =>
            {
                if (resource.Get(username) is not { } stored)
                    return NotFound(username);
                var write = UserWrite.From(stored, resource.Storage) with
                {
                    DiskQuota = request.DiskQuota,
                    TransferQuota = request.TransferQuota,
                    Bandwidth = request.Bandwidth,
                };
                if (await resource.ReplaceAsync(username, write, ct) is not { } saved)
                    return NotFound(username);
                return TypedResults.Ok(new QuotaSettingsModel(saved.DiskQuota, saved.TransferQuota, saved.Bandwidth));
            })
            .WithName("UpdateUserQuotas").WithSummary("Sets the quotas and the bandwidth of the user; a value that is not given is not set.")
            .WithValidationErrors().WithNotFound();

        users.MapPost("/{username}/quotas/scan", Results<Accepted, ProblemHttpResult> (UserResource resource, QuotaAdministrationService quotas,
                string username) =>
                resource.Get(username) != null && quotas.RequestScan(username) ? TypedResults.Accepted((string?)null) : NotFound(username))
            .WithName("ScanUserQuota").WithSummary("Queues a scan of the used space and files of every storage of the user with a disk quota.")
            .WithErrors().WithNotFound();

        users.MapPost("/{username}/quotas/transfer/reset", async Task<Results<NoContent, ProblemHttpResult>> (UserResource resource,
                QuotaAdministrationService quotas, string username, CancellationToken ct) =>
                resource.Get(username) != null && await quotas.ResetTransferAsync(username, ct) ? TypedResults.NoContent() : NotFound(username))
            .WithName("ResetUserTransferQuota").WithSummary("Sets the uploaded and downloaded bytes of the user to 0.").WithErrors().WithNotFound();
    }

    private static ProblemHttpResult NotFound(string username) => ApiResults.NotFound($"The user '{username}' does not exist.");
}
