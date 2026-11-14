using System.Net;
using System.Text.RegularExpressions;
using FxSsh.SshServerModule;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using SshServer.Administration;
using SshServer.Interfaces;
using SshServer.Interfaces.Net;

namespace SshServer.Api.Endpoints;

/// <summary>
/// The server settings that an administrator changes (the General and Access pages), without the host keys. On a save,
/// a value that is not given keeps its stored value.
/// </summary>
public sealed record SettingsModel
{
    public string? ServerBanner { get; init; }

    public int? ListenToPort { get; init; }

    public List<string>? BindToAddress { get; init; }

    public int? IdleTimeout { get; init; }

    public bool? EnableCommand { get; init; }

    public bool? EnableDirectTcpIp { get; init; }

    public List<string>? BlacklistedIps { get; init; }

    public bool? OnlyWhitelistedIps { get; init; }

    public List<string>? WhitelistedIps { get; init; }

    public int? MaxLoginAttemptsBeforeBan { get; init; }

    public int? LoginFailureWindowSeconds { get; init; }

    public int? BanDurationSeconds { get; init; }

    public bool? ExemptLoopbackFromBan { get; init; }

    public static SettingsModel From(ServerSettings s) => new()
    {
        ServerBanner = s.ServerBanner,
        ListenToPort = s.ListenToPort,
        BindToAddress = s.BindToAddress?.ToList() ?? [],
        IdleTimeout = s.IdleTimeout,
        EnableCommand = s.EnableCommand,
        EnableDirectTcpIp = s.EnableDirectTcpIp,
        BlacklistedIps = s.BlacklistedIps?.ToList() ?? [],
        OnlyWhitelistedIps = s.OnlyWhitelistedIps,
        WhitelistedIps = s.WhitelistedIps?.ToList() ?? [],
        MaxLoginAttemptsBeforeBan = s.MaxLoginAttemptsBeforeBan,
        LoginFailureWindowSeconds = s.LoginFailureWindowSeconds,
        BanDurationSeconds = s.BanDurationSeconds,
        ExemptLoopbackFromBan = s.ExemptLoopbackFromBan,
    };

    /// <summary>Writes the given values to <paramref name="settings"/> after the rules of the settings pages; throws when one is not valid.</summary>
    public void ApplyTo(ServerSettings settings)
    {
        var errors = new ValidationErrors();
        if (ListenToPort is < 1 or > 65535)
            errors.Add("listenToPort", "The port must be a number from 1 to 65535.");
        foreach (var address in BindToAddress ?? [])
        {
            if (!IPAddress.TryParse(address?.Trim(), out _))
                errors.Add("bindToAddress", $"'{address}' is not an IP address.");
        }
        if (ServerBanner is { } banner && (banner.Length > 200 || !Regex.IsMatch(banner, @"^[\x20-\x7E]*$")))
            errors.Add("serverBanner", "The banner can have at most 200 printable ASCII characters.");
        if (IdleTimeout is < 0 or > 86400)
            errors.Add("idleTimeout", "The idle timeout must be from 0 to 86400 seconds.");
        errors.AddRange("blacklistedIps", CidrNotation.FindInvalid(BlacklistedIps).Select(e => $"'{e}' is not an IP address or a network in CIDR notation."));
        errors.AddRange("whitelistedIps", CidrNotation.FindInvalid(WhitelistedIps).Select(e => $"'{e}' is not an IP address or a network in CIDR notation."));
        if (MaxLoginAttemptsBeforeBan is < 0 or > 1000)
            errors.Add("maxLoginAttemptsBeforeBan", "Use a number from 0 to 1000 (0 turns auto-ban off).");
        if (LoginFailureWindowSeconds is < 0 or > 31_536_000)
            errors.Add("loginFailureWindowSeconds", "Use a number of seconds from 0 to 31536000 (0 turns auto-ban off).");
        if (BanDurationSeconds is < 0 or > 31_536_000)
            errors.Add("banDurationSeconds", "Use a number of seconds from 0 to 31536000 (0 turns auto-ban off).");
        errors.ThrowIfAny();

        if (ServerBanner != null)
            settings.ServerBanner = string.IsNullOrWhiteSpace(ServerBanner) ? null : ServerBanner.Trim();
        settings.ListenToPort = ListenToPort ?? settings.ListenToPort;
        settings.BindToAddress = BindToAddress == null ? settings.BindToAddress : Entries(BindToAddress);
        settings.IdleTimeout = IdleTimeout ?? settings.IdleTimeout;
        settings.EnableCommand = EnableCommand ?? settings.EnableCommand;
        settings.EnableDirectTcpIp = EnableDirectTcpIp ?? settings.EnableDirectTcpIp;
        settings.BlacklistedIps = BlacklistedIps == null ? settings.BlacklistedIps : Entries(BlacklistedIps);
        settings.OnlyWhitelistedIps = OnlyWhitelistedIps ?? settings.OnlyWhitelistedIps;
        settings.WhitelistedIps = WhitelistedIps == null ? settings.WhitelistedIps : Entries(WhitelistedIps);
        settings.MaxLoginAttemptsBeforeBan = MaxLoginAttemptsBeforeBan ?? settings.MaxLoginAttemptsBeforeBan;
        settings.LoginFailureWindowSeconds = LoginFailureWindowSeconds ?? settings.LoginFailureWindowSeconds;
        settings.BanDurationSeconds = BanDurationSeconds ?? settings.BanDurationSeconds;
        settings.ExemptLoopbackFromBan = ExemptLoopbackFromBan ?? settings.ExemptLoopbackFromBan;
    }

    private static List<string> Entries(IEnumerable<string> entries) =>
        entries.Where(e => !string.IsNullOrWhiteSpace(e)).Select(e => e.Trim()).ToList();
}

/// <summary>The settings with the fingerprints of the host keys (never the keys).</summary>
public sealed record SettingsView(SettingsModel Settings, IReadOnlyList<HostKeyFingerprint> HostKeys);

/// <summary>
/// /api/v1/settings over <see cref="AdminScopedSettingsRepository"/>: every administrator reads them (the dashboard shows
/// them), a change needs ManageSettings. A change of the port or the addresses takes effect at the next start.
/// </summary>
internal static class SettingsEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        var settings = api.MapGroup("/settings").WithTags("Settings");

        settings.MapGet("/", (AdminScopedSettingsRepository repository) => TypedResults.Ok(View(repository.ServerSettings)))
            .WithName("GetSettings").WithErrors();

        settings.MapPut("/", (AdminScopedSettingsRepository repository, SettingsModel request) => Save(repository, request))
            .WithName("UpdateSettings").WithSummary("Saves the given settings; a value that is not given stays.")
            .RequireAuthorization(AdminPolicies.ManageSettings).WithValidationErrors();

        settings.MapPatch("/", (AdminScopedSettingsRepository repository, SettingsModel request) => Save(repository, request))
            .WithName("PatchSettings").WithSummary("Saves the given settings; a value that is not given (or null) stays.")
            .AcceptsMergePatch<SettingsModel>().RequireAuthorization(AdminPolicies.ManageSettings).WithValidationErrors();
    }

    private static Ok<SettingsView> Save(AdminScopedSettingsRepository repository, SettingsModel request)
    {
        var settings = repository.ServerSettings;
        request.ApplyTo(settings);
        if (!repository.UpdateServerSettings(settings))
            throw new InvalidOperationException("The server settings could not be saved.");
        return TypedResults.Ok(View(repository.ServerSettings));
    }

    private static SettingsView View(ServerSettings settings) => new(SettingsModel.From(settings), ServerInfo.GetHostKeyFingerprints(settings));
}
