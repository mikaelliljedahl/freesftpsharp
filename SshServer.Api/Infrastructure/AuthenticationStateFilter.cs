using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Administration;

namespace SshServer.Api;

/// <summary>
/// Gives the authenticated administrator of the request (bearer token or API key) to the scoped authentication state,
/// so <see cref="CurrentAdmin"/> and the scoped services behind the admin UI (<see cref="AdminScopedSettingsRepository"/>,
/// <see cref="ScopedConnections"/>, <see cref="ScopedAuditLog"/>) check the permissions and the scope of the API caller
/// in the same way as for a page. A route without login (the token, the health) gets no administrator, also when the
/// request has a login cookie of the UI.
/// </summary>
internal sealed class AuthenticationStateFilter : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var anonymous = http.GetEndpoint()?.Metadata.GetMetadata<IAllowAnonymous>() != null;
        var user = anonymous ? new ClaimsPrincipal(new ClaimsIdentity()) : http.User;
        if (http.RequestServices.GetService<AuthenticationStateProvider>() is IHostEnvironmentAuthenticationStateProvider state)
            state.SetAuthenticationState(Task.FromResult(new AuthenticationState(user)));
        return next(context);
    }
}
