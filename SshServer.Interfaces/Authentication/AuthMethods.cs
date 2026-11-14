namespace SshServer.Interfaces.Authentication;

/// <summary>The login methods of a user (issue #58). Flags, so that a user can allow several.</summary>
[Flags]
public enum AuthMethods
{
    None = 0,
    Password = 1,
    PublicKey = 2,

    /// <summary>Keyboard-interactive (#63). Allowed by default, so that a user keeps it when the server supports it.</summary>
    KeyboardInteractive = 4,

    All = Password | PublicKey | KeyboardInteractive,
}

/// <summary>The SSH names of the methods (RFC 4252 section 5) and the rules for the methods of a user.</summary>
public static class AuthMethodRules
{
    public const string PasswordName = "password";
    public const string PublicKeyName = "publickey";
    public const string KeyboardInteractiveName = "keyboard-interactive";

    /// <summary>The methods that can be steps of <see cref="User.RequireAllOf"/> today. Keyboard-interactive comes with #63.</summary>
    public static readonly IReadOnlyList<AuthMethods> StepMethods = [AuthMethods.PublicKey, AuthMethods.Password];

    /// <summary>The method of an SSH method name, or <see cref="AuthMethods.None"/> for "none", "hostbased" and unknown names.</summary>
    public static AuthMethods FromSshName(string? name) => name switch
    {
        PasswordName => AuthMethods.Password,
        PublicKeyName => AuthMethods.PublicKey,
        KeyboardInteractiveName => AuthMethods.KeyboardInteractive,
        _ => AuthMethods.None,
    };

    /// <summary>The SSH name of one method.</summary>
    public static string ToSshName(AuthMethods method) => method switch
    {
        AuthMethods.Password => PasswordName,
        AuthMethods.PublicKey => PublicKeyName,
        AuthMethods.KeyboardInteractive => KeyboardInteractiveName,
        _ => throw new ArgumentOutOfRangeException(nameof(method), method, "Not a single method."),
    };

    /// <summary>The steps of <see cref="User.RequireAllOf"/>, or an empty list: then one allowed method is enough.</summary>
    public static IReadOnlyList<AuthMethods> RequiredSteps(User user) => user.RequireAllOf is { Count: > 0 } steps ? steps : [];

    /// <summary>
    /// Checks the allowed methods and the required steps of a user. Returns the problems as texts for the operator; an
    /// empty list means the settings are valid.
    /// </summary>
    public static IReadOnlyList<string> Validate(AuthMethods allowed, IReadOnlyList<AuthMethods>? requireAllOf)
    {
        var problems = new List<string>();
        if ((allowed & AuthMethods.All) == AuthMethods.None)
            problems.Add("Allow at least one login method.");
        if ((allowed & ~AuthMethods.All) != AuthMethods.None)
            problems.Add("The allowed login methods contain an unknown method.");

        if (requireAllOf is not { Count: > 0 })
            return problems;

        if (requireAllOf.Count < 2)
            problems.Add("A multi-step login needs at least two methods.");
        foreach (var step in requireAllOf)
        {
            if (!StepMethods.Contains(step))
                problems.Add($"{step} cannot be a step of a multi-step login.");
            else if ((allowed & step) != step)
                problems.Add($"The multi-step login needs {step}, but {step} is not an allowed method.");
        }
        if (requireAllOf.Distinct().Count() != requireAllOf.Count)
            problems.Add("A method can be only once in a multi-step login.");
        return problems;
    }
}
