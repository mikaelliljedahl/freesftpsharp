using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using SshServer.Administration;
using SshServer.EventRules;
using SshServer.Interfaces.EventRules;
using JsonOptions = Microsoft.AspNetCore.Http.Json.JsonOptions;

namespace SshServer.Api.Endpoints;

/// <summary>An event rule (#68) in the API.</summary>
public sealed record EventRuleView(int Id, string Name, string? Description, bool Enabled, EventRuleTrigger Trigger, IReadOnlyList<string> EventTypes,
    string? CronExpression, string? TimeZone, EventRuleConditions Conditions, IReadOnlyList<EventRuleAction> Actions, DateTime? LastScheduledRunUtc)
{
    public static EventRuleView From(EventRule r) => new(r.Id, r.Name, r.Description, r.Enabled, r.Trigger, [.. r.EventTypes], r.CronExpression,
        r.TimeZone, r.Conditions, [.. r.Actions], r.LastScheduledRunUtc);
}

/// <summary>An event rule to create or save; a value that is not given gets its default.</summary>
public sealed record EventRuleWrite
{
    public string? Name { get; init; }

    public string? Description { get; init; }

    public bool? Enabled { get; init; }

    /// <summary>Event (default), Schedule or OnDemand.</summary>
    public EventRuleTrigger? Trigger { get; init; }

    /// <summary>For Event: "Category.Type" names, for example "File.Upload".</summary>
    public List<string>? EventTypes { get; init; }

    /// <summary>For Schedule: a cron expression (five fields).</summary>
    public string? CronExpression { get; init; }

    /// <summary>For Schedule: an IANA or Windows time zone; default UTC.</summary>
    public string? TimeZone { get; init; }

    public EventRuleConditions? Conditions { get; init; }

    /// <summary>The actions in order; their options are in GET /api/v1/event-rules/action-types.</summary>
    public List<EventRuleAction>? Actions { get; init; }

    public static EventRuleWrite From(EventRule r) => new()
    {
        Name = r.Name,
        Description = r.Description,
        Enabled = r.Enabled,
        Trigger = r.Trigger,
        EventTypes = [.. r.EventTypes],
        CronExpression = r.CronExpression,
        TimeZone = r.TimeZone,
        Conditions = r.Conditions,
        Actions = [.. r.Actions],
    };

    public EventRuleInput ToInput(int? id) => new()
    {
        Id = id,
        Name = Name ?? "",
        Description = Description,
        Enabled = Enabled ?? true,
        Trigger = Trigger ?? EventRuleTrigger.Event,
        EventTypes = EventTypes ?? [],
        CronExpression = CronExpression,
        TimeZone = TimeZone,
        Conditions = Conditions ?? new EventRuleConditions(),
        Actions = Actions ?? [],
    };
}

/// <summary>An action type and its options.</summary>
public sealed record EventActionTypeView(string Type, string DisplayName, string Description, bool NeedsUser, IReadOnlyList<EventActionField> Fields);

/// <summary>One run of a rule.</summary>
public sealed record EventRuleRunView(long Id, DateTime StartedUtc, long DurationMs, EventRuleRunStatus Status, string Trigger, string? Username, string Message)
{
    public static EventRuleRunView From(EventRuleRun r) => new(r.Id, r.StartedUtc, r.DurationMs, r.Status, r.Trigger, r.Username, r.Message);
}

/// <summary>/api/v1/event-rules over <see cref="EventRuleAdministrationService"/>, the service of the Event rules page (ManageEvents).</summary>
internal static class EventRuleEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        var rules = api.MapGroup("/event-rules").WithTags("Event rules").RequireAuthorization(AdminPolicies.ManageEvents);

        rules.MapGet("/", async (EventRuleAdministrationService service, CurrentAdmin current, int? offset, int? limit, CancellationToken ct) =>
                TypedResults.Ok(Paging.Of(await service.ListAsync(current.Actor, ct), offset, limit, EventRuleView.From)))
            .WithName("ListEventRules").WithValidationErrors();

        rules.MapGet("/action-types", (EventRuleAdministrationService service) =>
                TypedResults.Ok(service.ActionTypes.Select(a => new EventActionTypeView(a.Type, a.DisplayName, a.Description, a.NeedsUser, a.Fields)).ToList()))
            .WithName("ListEventActionTypes").WithSummary("The action types and their options.").WithErrors();

        rules.MapGet("/{id:int}", async Task<Results<Ok<EventRuleView>, ProblemHttpResult>> (EventRuleAdministrationService service, CurrentAdmin current,
                int id, CancellationToken ct) =>
                await service.GetAsync(current.Actor, id, ct) is { } rule ? TypedResults.Ok(EventRuleView.From(rule)) : NotFound(id))
            .WithName("GetEventRule").WithErrors().WithNotFound();

        rules.MapPost("/", async (EventRuleAdministrationService service, CurrentAdmin current, EventRuleWrite request, CancellationToken ct) =>
            {
                var id = await SaveAsync(service, current, request.ToInput(null), ct);
                return TypedResults.Created($"/api/v1/event-rules/{id}", EventRuleView.From((await service.GetAsync(current.Actor, id, ct))!));
            })
            .WithName("CreateEventRule").WithValidationErrors();

        rules.MapPut("/{id:int}", async Task<Results<Ok<EventRuleView>, ProblemHttpResult>> (EventRuleAdministrationService service, CurrentAdmin current,
                int id, EventRuleWrite request, CancellationToken ct) => await ReplaceAsync(service, current, id, request, ct))
            .WithName("ReplaceEventRule").WithValidationErrors().WithNotFound();

        rules.MapPatch("/{id:int}", async Task<Results<Ok<EventRuleView>, ProblemHttpResult>> (EventRuleAdministrationService service, CurrentAdmin current,
                IOptions<JsonOptions> json, int id, HttpRequest request, CancellationToken ct) =>
            {
                if (await service.GetAsync(current.Actor, id, ct) is not { } stored)
                    return NotFound(id);
                var write = MergePatch.Apply(EventRuleWrite.From(stored), await MergePatch.ReadAsync(request), json.Value.SerializerOptions);
                return await ReplaceAsync(service, current, id, write, ct);
            })
            .WithName("PatchEventRule").AcceptsMergePatch<EventRuleWrite>().WithValidationErrors().WithNotFound();

        rules.MapDelete("/{id:int}", async Task<Results<NoContent, ProblemHttpResult>> (EventRuleAdministrationService service, CurrentAdmin current,
                int id, CancellationToken ct) =>
                await service.RemoveAsync(current.Actor, id, ct) ? TypedResults.NoContent() : NotFound(id))
            .WithName("DeleteEventRule").WithErrors().WithNotFound();

        rules.MapPost("/{id:int}/run", async Task<Results<Ok<List<EventRuleRunView>>, ProblemHttpResult>> (EventRuleAdministrationService service,
                CurrentAdmin current, int id, CancellationToken ct) =>
                await service.RunNowAsync(current.Actor, id, ct) is { } runs
                    ? TypedResults.Ok(runs.Select(EventRuleRunView.From).ToList())
                    : ApiResults.NotFound($"The event rule {id} does not exist or runs only on events."))
            .WithName("RunEventRule").WithSummary("Runs a scheduled or on-demand rule now and returns its runs.").WithErrors().WithNotFound();

        rules.MapGet("/{id:int}/runs", async Task<Results<Ok<List<EventRuleRunView>>, ProblemHttpResult>> (EventRuleAdministrationService service,
                CurrentAdmin current, int id, CancellationToken ct) =>
            {
                if (await service.GetAsync(current.Actor, id, ct) == null)
                    return NotFound(id);
                return TypedResults.Ok((await service.ListRunsAsync(current.Actor, id, ct)).Select(EventRuleRunView.From).ToList());
            })
            .WithName("ListEventRuleRuns").WithSummary("The last runs of the rule.").WithErrors().WithNotFound();
    }

    private static async Task<Results<Ok<EventRuleView>, ProblemHttpResult>> ReplaceAsync(EventRuleAdministrationService service, CurrentAdmin current,
        int id, EventRuleWrite request, CancellationToken ct)
    {
        if (await service.GetAsync(current.Actor, id, ct) == null)
            return NotFound(id);
        await SaveAsync(service, current, request.ToInput(id), ct);
        return TypedResults.Ok(EventRuleView.From((await service.GetAsync(current.Actor, id, ct))!));
    }

    private static async Task<int> SaveAsync(EventRuleAdministrationService service, CurrentAdmin current, EventRuleInput input, CancellationToken ct)
    {
        var result = await service.SaveAsync(current.Actor, input, ct);
        if (!result.Succeeded)
            throw new ApiValidationException(new Dictionary<string, string[]> { [""] = result.Errors.ToArray() });
        return result.Id!.Value;
    }

    private static ProblemHttpResult NotFound(int id) => ApiResults.NotFound($"The event rule {id} does not exist.");
}
