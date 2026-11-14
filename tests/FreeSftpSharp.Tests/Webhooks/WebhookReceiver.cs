using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace FreeSftpSharp.Tests.Webhooks;

/// <summary>A request that the <see cref="WebhookReceiver"/> got.</summary>
public sealed record ReceivedRequest(string Method, string Path, IReadOnlyDictionary<string, string> Headers, string Body, DateTimeOffset ReceivedAt)
{
    public string? Header(string name) => Headers.TryGetValue(name, out var value) ? value : null;

    public JsonElement Json => JsonDocument.Parse(Body).RootElement;
}

/// <summary>The answer of the <see cref="WebhookReceiver"/>: a status, a body, and a wait before it.</summary>
public sealed record ReceiverAnswer(int Status, string? Body = null, TimeSpan Delay = default, string? Location = null);

/// <summary>
/// An HTTP receiver of webhooks on Kestrel, in the test process, on a free loopback port. It keeps every request and
/// answers with <see cref="Respond"/> (default 200).
/// </summary>
public sealed class WebhookReceiver : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly ConcurrentQueue<ReceivedRequest> _requests = new();
    private readonly Func<DateTimeOffset> _clock;

    private WebhookReceiver(WebApplication app, Func<DateTimeOffset> clock)
    {
        _app = app;
        _clock = clock;
    }

    /// <summary>The answer for a request and the number of requests before it (0 for the first).</summary>
    public Func<ReceivedRequest, int, ReceiverAnswer> Respond { get; set; } = (_, _) => new ReceiverAnswer(200);

    public string BaseUrl { get; private set; } = string.Empty;

    public string Url(string path = "/hook") => BaseUrl + path;

    public IReadOnlyList<ReceivedRequest> Requests => _requests.ToArray();

    /// <param name="clock">The time that is kept with each request. Default: the system clock.</param>
    public static async Task<WebhookReceiver> StartAsync(Func<DateTimeOffset>? clock = null)
    {
        // An empty builder reads no appsettings.json, environment variables or command line, so no endpoint
        // (Kestrel:Endpoints, ASPNETCORE_URLS) of the machine or of an appsettings.json in the test output can reach it.
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        builder.Services.AddLogging();
        builder.WebHost.UseKestrelCore().ConfigureKestrel(o => o.Listen(IPAddress.Loopback, 0));
        var app = builder.Build();
        var receiver = new WebhookReceiver(app, clock ?? (() => DateTimeOffset.UtcNow));
        app.Run(receiver.HandleAsync);
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        receiver.BaseUrl = address.TrimEnd('/');
        return receiver;
    }

    private async Task HandleAsync(HttpContext context)
    {
        using var reader = new StreamReader(context.Request.Body);
        var body = await reader.ReadToEndAsync(context.RequestAborted);
        var headers = context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString(), StringComparer.OrdinalIgnoreCase);
        var request = new ReceivedRequest(context.Request.Method, context.Request.Path, headers, body, _clock());
        int index;
        lock (_requests)
        {
            index = _requests.Count;
            _requests.Enqueue(request);
        }

        var answer = Respond(request, index);
        if (answer.Delay > TimeSpan.Zero)
        {
            try
            {
                await Task.Delay(answer.Delay, context.RequestAborted);
            }
            catch (OperationCanceledException)
            {
                return; // the client gave up
            }
        }
        context.Response.StatusCode = answer.Status;
        if (answer.Location != null)
            context.Response.Headers.Location = answer.Location;
        if (answer.Body != null)
            await context.Response.WriteAsync(answer.Body, context.RequestAborted);
    }

    /// <summary>Waits until at least <paramref name="count"/> matching requests are here; returns them.</summary>
    public async Task<IReadOnlyList<ReceivedRequest>> WaitForAsync(int count = 1, Func<ReceivedRequest, bool>? predicate = null, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(15));
        while (true)
        {
            var found = Requests.Where(r => predicate == null || predicate(r)).ToList();
            if (found.Count >= count)
                return found;
            if (DateTime.UtcNow > deadline)
                throw new TimeoutException($"Expected {count} request(s), got {found.Count}.");
            await Task.Delay(10);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}
