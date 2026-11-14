using System.Numerics;

namespace SshServer.Interfaces;

/// <summary>
/// Flag enums in JSON as arrays of names (<c>["List","Download"]</c>), not as numbers or comma lists: the REST API (#67)
/// and the answer of the authentication hook (#136) use the same rules. The output has the single flags; the input also
/// takes a combined name such as <c>All</c>. Names are compared without case.
/// </summary>
public static class FlagNames
{
    public static IReadOnlyList<string> Of<T>(T value) where T : struct, Enum
    {
        var bits = Convert.ToInt64(value);
        return Enum.GetValues<T>()
            .Where(f => BitOperations.PopCount((ulong)Convert.ToInt64(f)) == 1 && (bits & Convert.ToInt64(f)) == Convert.ToInt64(f))
            .Select(f => f.ToString())
            .ToList();
    }

    /// <summary>The flags of the names; the unknown names are in <paramref name="unknown"/>.</summary>
    public static T Parse<T>(IEnumerable<string>? names, List<string> unknown) where T : struct, Enum
    {
        long bits = 0;
        foreach (var name in names ?? [])
        {
            if (!string.IsNullOrWhiteSpace(name) && !name.Trim().All(char.IsDigit)
                && Enum.TryParse<T>(name.Trim(), ignoreCase: true, out var flag) && Enum.IsDefined(flag))
                bits |= Convert.ToInt64(flag);
            else
                unknown.Add(name ?? "");
        }
        return (T)Enum.ToObject(typeof(T), bits);
    }
}
