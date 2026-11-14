using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using JsonOptions = Microsoft.AspNetCore.Http.Json.JsonOptions;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using SshServer.Administration;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Webhooks;
using SshServer.Webhooks;

namespace SshServer.Api.Endpoints;

/// <summary>A webhook (#66) in the API. The signing secret is write-only: only whether it is set.</summary>
public sealed record WebhookView(int Id, string Name, string Url, string Method, bool HasSecret, IReadOnlyDictionary<string, string> Headers,
    IReadOnlyList<string> EventTypes, IReadOnlyList<string> Users, string? PathGlob, bool Sync, bool FailOpen, int TimeoutSeconds, bool Enabled)
{
    public static WebhookView From(Webhook w) => new(w.Id, w.Name, w.Url, w.Method, !string.IsNullOrEmpty(w.ProtectedSecret),
        new Dictionary<string, string>(w.Headers), [.. w.EventTypes], [.. w.Users], w.PathGlob, w.Sync, w.FailOpen, w.TimeoutSeconds, w.Enabled);
}

/// <summary>A webhook to create or save. <see cref="Secret"/> is write-only: on a save without it the stored one stays.</summary>
public sealed record WebhookWrite
{
    public string? Name { get; init; }

    public string? Url { get; init; }

    /// <summary>POST (default) or PUT.</summary>
    public string? Method { get; init; }

    public string? Secret { get; init; }

    public bool? RemoveSecret { get; init; }

    public Dictionary<string, string>? Headers { get; init; }

    /// <summary>"Category.Type" names, for example "File.Upload". Empty: every event except the Pre* events.</summary>
    public List<string>? EventTypes { get; init; }

    public List<string>? Users { get; init; }

    public string? PathGlob { get; init; }

    public bool? Sync { get; init; }

    public bool? FailOpen { get; init; }

    public int? TimeoutSeconds { get; init; }

    public bool? Enabled { get; init; }

    public static WebhookWrite From(Webhook w) => new()
    {
        Name = w.Name,
        Url = w.Url,
        Method = w.Method,
        Headers = new Dictionary<string, string>(w.Headers),
        EventTypes = [.. w.EventTypes],
        Users = [.. w.Users],
        PathGlob = w.PathGlob,
        Sync = w.Sync,
        FailOpen = w.FailOpen,
        TimeoutSeconds = w.TimeoutSeconds,
        Enabled = w.Enabled,
    };

    public WebhookInput ToInput(int? id) => new()
    {
        Id = id,
        Name = Name ?? "",
        Url = Url ?? "",
        Method = string.IsNullOrWhiteSpace(Method) ? Webhook.MethodPost : Method.Trim().ToUpperInvariant(),
        NewSecret = Secret,
        RemoveSecret = RemoveSecret ?? false,
        Headers = Headers ?? [],
        EventTypes = EventTypes ?? [],
        Users = Users ?? [],
        PathGlob = PathGlob,
        Sync = Sync ?? false,
        FailOpen = FailOpen ?? false,
        TimeoutSeconds = TimeoutSeconds ?? Webhook.DefaultTimeoutSeconds,
        Enabled = Enabled ?? true,
    };
}

/// <summary>One delivery of a webhook (the outbox).</summary>
public sealed record WebhookDeliveryView(long Id, Guid DeliveryId, Guid EventId, string EventType, string Status, int Attempts,
    DateTime CreatedUtc, DateTime? NextAttemptUtc, DateTime? LastAttemptUtc, int? LastStatusCode, string? LastError)
{
    public static WebhookDeliveryView From(WebhookDelivery d) => new(d.Id, d.DeliveryId, d.EventId, d.EventType, d.Status.ToString(), d.Attempts,
        d.CreatedUtc, d.NextAttemptUtc, d.LastAttemptUtc, d.LastStatusCode, d.LastError);
}

/// <summary>/api/v1/webhooks over <see cref="WebhookAdministrationService"/>, the service of the Webhooks page (ManageEvents).</summary>
internal static class WebhookEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        var webhooks = api.MapGroup("/webhooks").WithTags("Webhooks").RequireAuthorization(AdminPolicies.ManageEvents);

        webhooks.MapGet("/", async (WebhookAdministrationService service, CurrentAdmin current, int? offset, int? limit, CancellationToken ct) =>
                TypedResults.Ok(Paging.Of(await service.ListAsync(current.Actor, ct), offset, limit, WebhookView.From)))
            .WithName("ListWebhooks").WithValidationErrors();

        webhooks.MapGet("/event-types", () => TypedResults.Ok(EventNames.Groups.SelectMany(g => g.Names).ToList()))
            .WithName("ListWebhookEventTypes").WithSummary("The event names for the eventTypes filter.").WithErrors();

        webhooks.MapGet("/{id:int}", async Task<Results<Ok<WebhookView>, ProblemHttpResult>> (WebhookAdministrationService service, CurrentAdmin current, int id, CancellationToken ct) =>
                await service.GetAsync(current.Actor, id, ct) is { } webhook ? TypedResults.Ok(WebhookView.From(webhook)) : NotFound(id))
            .WithName("GetWebhook").WithErrors().WithNotFound();

        webhooks.MapPost("/", async (WebhookAdministrationService service, CurrentAdmin current, WebhookWrite request, CancellationToken ct) =>
            {
                var id = await SaveAsync(service, current, request.ToInput(null), ct);
                return TypedResults.Created($"/api/v1/webhooks/{id}", WebhookView.From((await service.GetAsync(current.Actor, id, ct))!));
            })
            .WithName("CreateWebhook").WithValidationErrors();

        webhooks.MapPut("/{id:int}", async Task<Results<Ok<WebhookView>, ProblemHttpResult>> (WebhookAdministrationService service, CurrentAdmin current, int id,
                WebhookWrite request, CancellationToken ct) => await ReplaceAsync(service, current, id, request, ct))
            .WithName("ReplaceWebhook").WithValidationErrors().WithNotFound();

        webhooks.MapPatch("/{id:int}", async Task<Results<Ok<WebhookView>, ProblemHttpResult>> (WebhookAdministrationService service, CurrentAdmin current,
                IOptions<JsonOptions> json, int id, HttpRequest request, CancellationToken ct) =>
            {
                if (await service.GetAsync(current.Actor, id, ct) is not { } stored)
                    return NotFound(id);
                return await ReplaceAsync(service, current, id, MergePatch.Apply(WebhookWrite.From(stored), await MergePatch.ReadAsync(request), json.Value.SerializerOptions), ct);
            })
            .WithName("PatchWebhook").AcceptsMergePatch<WebhookWrite>().WithValidationErrors().WithNotFound();

        webhooks.MapDelete("/{id:int}", async Task<Results<NoContent, ProblemHttpResult>> (WebhookAdministrationService service, CurrentAdmin current, int id, CancellationToken ct) =>
                await service.RemoveAsync(current.Actor, id, ct) ? TypedResults.NoContent() : NotFound(id))
            .WithName("DeleteWebhook").WithErrors().WithNotFound();

        webhooks.MapPost("/{id:int}/test", async Task<Results<Accepted, ProblemHttpResult>> (WebhookAdministrationService service, CurrentAdmin current, int id, CancellationToken ct) =>
                await service.SendTestAsync(current.Actor, id, ct) ? TypedResults.Accepted((string?)null) : NotFound(id))
            .WithName("TestWebhook").WithSummary("Puts a test event for the webhook in the outbox.").WithErrors().WithNotFound();

        webhooks.MapGet("/{id:int}/deliveries", async Task<Results<Ok<List<WebhookDeliveryView>>, ProblemHttpResult>> (WebhookAdministrationService service, CurrentAdmin current,
                int id, CancellationToken ct) =>
            {
                if (await service.GetAsync(current.Actor, id, ct) == null)
                    return NotFound(id);
                return TypedResults.Ok((await service.ListDeliveriesAsync(current.Actor, id, ct)).Select(WebhookDeliveryView.From).ToList());
            })
            .WithName("ListWebhookDeliveries").WithSummary("The last deliveries of the webhook.").WithErrors().WithNotFound();

        webhooks.MapPost("/deliveries/{deliveryId:long}/redeliver", async Task<Results<Accepted, ProblemHttpResult>> (WebhookAdministrationService service, CurrentAdmin current,
                long deliveryId, CancellationToken ct) =>
                await service.RedeliverAsync(current.Actor, deliveryId, ct)
                    ? TypedResults.Accepted((string?)null)
                    : ApiResults.NotFound($"The delivery {deliveryId} does not exist or cannot be sent again."))
            .WithName("RedeliverWebhook").WithSummary("Sends an asynchronous delivery again, now.").WithErrors().WithNotFound();
    }

    private static async Task<Results<Ok<WebhookView>, ProblemHttpResult>> ReplaceAsync(WebhookAdministrationService service, CurrentAdmin current, int id,
        WebhookWrite request, CancellationToken ct)
    {
        if (await service.GetAsync(current.Actor, id, ct) == null)
            return NotFound(id);
        await SaveAsync(service, current, request.ToInput(id), ct);
        return TypedResults.Ok(WebhookView.From((await service.GetAsync(current.Actor, id, ct))!));
    }

    private static ProblemHttpResult NotFound(int id) => ApiResults.NotFound($"The webhook {id} does not exist.");

    private static async Task<int> SaveAsync(WebhookAdministrationService service, CurrentAdmin current, WebhookInput input, CancellationToken ct)
    {
        var result = await service.SaveAsync(current.Actor, input, ct);
        if (!result.Succeeded)
            throw new ApiValidationException(new Dictionary<string, string[]> { [""] = result.Errors.ToArray() });
        return result.Id!.Value;
    }
}
