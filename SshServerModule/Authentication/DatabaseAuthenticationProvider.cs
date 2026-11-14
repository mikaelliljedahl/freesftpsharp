#nullable enable
using System;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.SshServerModule;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;

namespace SshServerModule.Authentication;

/// <summary>
/// The built-in provider (issue #64): the stored password hash and public keys of a local user (<see cref="UserLogics"/>).
/// A user name that is not stored is not handled, so the next provider can know it.
/// </summary>
public sealed class DatabaseAuthenticationProvider : IAuthenticationProvider
{
    public const string ProviderName = "database";

    private readonly ISettingsRepository _repository;
    private readonly ILogger _logger;
    private readonly TimeProvider _time;

    public DatabaseAuthenticationProvider(ISettingsRepository repository, ILogger<DatabaseAuthenticationProvider>? logger = null,
        TimeProvider? time = null)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _logger = (ILogger?)logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
        _time = time ?? TimeProvider.System;
    }

    public string Name => ProviderName;

    public ValueTask<AuthResult> AuthenticateAsync(AuthRequest request, CancellationToken ct)
    {
        var user = request.StoredUser;
        if (user == null)
            return ValueTask.FromResult(AuthResult.NotHandled);

        if (request.PublicKey != null)
            return ValueTask.FromResult(UserLogics.VerifyUserKey(user, request.PublicKey, _time.GetUtcNow().UtcDateTime)
                ? AuthResult.Success()
                : AuthResult.Failure("the public key is not accepted"));

        if (request.Password != null)
            return ValueTask.FromResult(UserLogics.VerifyUserPassword(user, request.Password, _repository, _logger)
                ? AuthResult.Success()
                : AuthResult.Failure("wrong password"));

        return ValueTask.FromResult(AuthResult.Failure("the method is not supported"));
    }
}
