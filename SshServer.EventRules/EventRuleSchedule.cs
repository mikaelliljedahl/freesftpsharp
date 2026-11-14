using Cronos;

namespace SshServer.EventRules;

/// <summary>The cron expressions of the scheduled rules (Cronos): five fields (minute hour day month weekday) or a macro such as <c>@daily</c>.</summary>
public static class EventRuleSchedule
{
    /// <summary>Throws <see cref="CronFormatException"/> when the expression is not valid.</summary>
    public static CronExpression ParseCron(string? expression)
    {
        if (string.IsNullOrWhiteSpace(expression))
            throw new CronFormatException("Enter a cron expression, for example 0 3 * * * (every day at 03:00).");
        return CronExpression.Parse(expression.Trim(), CronFormat.Standard);
    }

    /// <summary>The time zone (IANA or Windows id); UTC for an empty id. Throws <see cref="TimeZoneNotFoundException"/>.</summary>
    public static TimeZoneInfo ParseTimeZone(string? id)
        => string.IsNullOrWhiteSpace(id) ? TimeZoneInfo.Utc : TimeZoneInfo.FindSystemTimeZoneById(id.Trim());

    /// <summary>The latest occurrence after <paramref name="fromUtc"/> and at or before <paramref name="toUtc"/>; null: none.</summary>
    public static DateTime? LastOccurrence(CronExpression cron, TimeZoneInfo zone, DateTime fromUtc, DateTime toUtc)
    {
        DateTime? last = null;
        foreach (var occurrence in cron.GetOccurrences(fromUtc, toUtc, zone, fromInclusive: false, toInclusive: true))
            last = occurrence;
        return last;
    }

    /// <summary>The next occurrence after <paramref name="fromUtc"/>; null: none.</summary>
    public static DateTime? Next(CronExpression cron, TimeZoneInfo zone, DateTime fromUtc)
        => cron.GetNextOccurrence(fromUtc, zone, inclusive: false);
}
