using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;

namespace SshServer.Api;

/// <summary>The problem details results of the API.</summary>
internal static class ApiResults
{
    public static ProblemHttpResult NotFound(string detail) =>
        TypedResults.Problem(detail, statusCode: StatusCodes.Status404NotFound, title: "Not found");

    public static ProblemHttpResult Forbidden(string detail) =>
        TypedResults.Problem(detail, statusCode: StatusCodes.Status403Forbidden, title: "Forbidden");

    /// <summary>The OpenAPI metadata of the errors that every authenticated route can give.</summary>
    public static RouteHandlerBuilder WithErrors(this RouteHandlerBuilder builder) => builder
        .ProducesProblem(StatusCodes.Status401Unauthorized)
        .ProducesProblem(StatusCodes.Status403Forbidden);

    public static RouteHandlerBuilder WithValidationErrors(this RouteHandlerBuilder builder) => builder
        .WithErrors()
        .ProducesValidationProblem();

    public static RouteHandlerBuilder WithNotFound(this RouteHandlerBuilder builder) => builder
        .ProducesProblem(StatusCodes.Status404NotFound);

    /// <summary>The body type of a JSON merge patch route, for the OpenAPI document.</summary>
    public static RouteHandlerBuilder AcceptsMergePatch<T>(this RouteHandlerBuilder builder) where T : notnull =>
        builder.Accepts<T>("application/merge-patch+json", "application/json");

}
