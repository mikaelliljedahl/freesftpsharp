namespace SshServer.Api;

/// <summary>
/// Invalid input of an API request: the problems by field (camelCase names of the request body, "" for the whole
/// request). <see cref="ApiExceptionFilter"/> answers 400 with RFC 9457 validation problem details.
/// </summary>
public sealed class ApiValidationException : Exception
{
    public ApiValidationException(IDictionary<string, string[]> errors)
        : base("The request is not valid.")
    {
        Errors = errors;
    }

    public ApiValidationException(string field, string error)
        : this(new Dictionary<string, string[]> { [field] = [error] })
    {
    }

    public IDictionary<string, string[]> Errors { get; }
}

/// <summary>Collects validation problems by field.</summary>
public sealed class ValidationErrors
{
    private readonly Dictionary<string, List<string>> _errors = new(StringComparer.Ordinal);

    public bool HasErrors => _errors.Count > 0;

    public void Add(string field, string? error)
    {
        if (string.IsNullOrEmpty(error))
            return;
        if (!_errors.TryGetValue(field, out var list))
            _errors[field] = list = new List<string>();
        list.Add(error);
    }

    public void AddRange(string field, IEnumerable<string> errors)
    {
        foreach (var error in errors)
            Add(field, error);
    }

    /// <summary>Throws <see cref="ApiValidationException"/> when there is a problem.</summary>
    public void ThrowIfAny()
    {
        if (HasErrors)
            throw new ApiValidationException(_errors.ToDictionary(e => e.Key, e => e.Value.ToArray()));
    }
}

/// <summary>The object exists already. <see cref="ApiExceptionFilter"/> answers 409.</summary>
public sealed class ApiConflictException : Exception
{
    public ApiConflictException(string message) : base(message)
    {
    }
}
