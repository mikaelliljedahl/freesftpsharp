using SshServer.Interfaces.Admins;

namespace SshServer.Api.Authentication;

/// <summary>
/// The second factor of <c>POST /api/v1/token</c>. The admin two-factor login (#63) registers its own implementation
/// (replace this service); until then no administrator needs one. API keys need no second factor: an administrator
/// creates them after its login.
/// </summary>
public interface ITokenSecondFactor
{
    /// <summary>True when <paramref name="code"/> (the <c>totpCode</c> of the request, may be null) is enough for the administrator.</summary>
    Task<bool> IsSatisfiedAsync(Admin admin, string? code, CancellationToken ct);
}

/// <summary>No second factor (the default until #63).</summary>
internal sealed class NoTokenSecondFactor : ITokenSecondFactor
{
    public Task<bool> IsSatisfiedAsync(Admin admin, string? code, CancellationToken ct) => Task.FromResult(true);
}
