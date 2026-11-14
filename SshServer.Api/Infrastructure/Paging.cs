namespace SshServer.Api;

/// <summary>One page of a list: <see cref="Items"/> from <see cref="Offset"/>, and the number of all matching items.</summary>
public sealed record Page<T>(IReadOnlyList<T> Items, int Total, int Offset, int Limit);

/// <summary>The paging parameters <c>?offset=&amp;limit=</c> of the list routes.</summary>
internal static class Paging
{
    public const int DefaultLimit = 100;
    public const int MaximumLimit = 1000;

    public static (int Offset, int Limit) Validate(int? offset, int? limit)
    {
        var errors = new ValidationErrors();
        if (offset is < 0)
            errors.Add("offset", "The offset cannot be negative.");
        if (limit is < 1 or > MaximumLimit)
            errors.Add("limit", $"The limit must be from 1 to {MaximumLimit}.");
        errors.ThrowIfAny();
        return (offset ?? 0, limit ?? DefaultLimit);
    }

    public static Page<TOut> Of<TIn, TOut>(IEnumerable<TIn> all, int? offset, int? limit, Func<TIn, TOut> map)
    {
        var (skip, take) = Validate(offset, limit);
        var list = all as IReadOnlyCollection<TIn> ?? all.ToList();
        return new Page<TOut>(list.Skip(skip).Take(take).Select(map).ToList(), list.Count, skip, take);
    }
}
