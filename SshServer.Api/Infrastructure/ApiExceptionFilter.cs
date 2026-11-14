using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using FxSsh.SshServerModule.Security;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Users;

namespace SshServer.Api;

/// <summary>
/// Turns the exceptions of the application services into RFC 9457 problem details, so every API error has the same
/// form: a missing permission is 403, invalid input 400 (with the problems by field), anything else 500 (logged, with
/// no details for the client).
/// </summary>
internal sealed class ApiExceptionFilter : IEndpointFilter
{
    private readonly ILogger<ApiExceptionFilter> _logger;

    public ApiExceptionFilter(ILogger<ApiExceptionFilter> logger)
    {
        _logger = logger;
    }

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            return await next(context);
        }
        catch (ApiValidationException ex)
        {
            return Results.ValidationProblem(ex.Errors, title: ex.Message);
        }
        catch (ApiConflictException ex)
        {
            return Results.Problem(ex.Message, statusCode: StatusCodes.Status409Conflict, title: "Conflict");
        }
        catch (AdminAccessDeniedException ex)
        {
            return Results.Problem(ex.Message, statusCode: StatusCodes.Status403Forbidden, title: "Forbidden");
        }
        catch (Exception ex) when (ex is AdminAdministrationException or UserAdministrationException)
        {
            return Results.ValidationProblem(new Dictionary<string, string[]> { [""] = [ex.Message] }, title: "The request is not valid.");
        }
        catch (JsonException ex)
        {
            return Results.ValidationProblem(new Dictionary<string, string[]> { [ex.Path ?? ""] = ["The value is not valid here."] },
                title: "The request body is not valid.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "REST API request {Method} {Path} failed.", LogText.Clean(context.HttpContext.Request.Method),
                LogText.Clean(context.HttpContext.Request.Path.Value));
            return Results.Problem("The server could not complete the request. The server log has the details.",
                statusCode: StatusCodes.Status500InternalServerError);
        }
    }
}
