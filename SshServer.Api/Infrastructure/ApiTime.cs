namespace SshServer.Api;

/// <summary>The times of the API are UTC: a time without an offset (also one read back from the database) is UTC, never local.</summary>
internal static class ApiTime
{
    public static DateTime ToUtc(DateTime value) =>
        value.Kind == DateTimeKind.Local ? value.ToUniversalTime() : DateTime.SpecifyKind(value, DateTimeKind.Utc);

    public static DateTime? ToUtc(DateTime? value) => value is { } v ? ToUtc(v) : null;
}
