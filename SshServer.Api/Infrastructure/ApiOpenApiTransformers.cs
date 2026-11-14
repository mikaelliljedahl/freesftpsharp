using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;
using SshServer.Api.Authentication;

namespace SshServer.Api;

/// <summary>
/// The title, the two security schemes (bearer token and API key) and no server URLs (the document is the same on every
/// host, so the committed docs/openapi.json can be compared with it).
/// </summary>
internal sealed class ApiDocumentTransformer : IOpenApiDocumentTransformer
{
    public const string BearerSchemeName = "bearer";
    public const string ApiKeySchemeName = "apiKey";

    public Task TransformAsync(OpenApiDocument document, OpenApiDocumentTransformerContext context, CancellationToken cancellationToken)
    {
        document.Info = new OpenApiInfo
        {
            Title = "FreeSftpSharp REST API",
            Version = "v1",
            Description = "Administration of FreeSftpSharp. Every route needs a bearer token (POST /api/v1/token) or an API key " +
                          $"({ApiAuthentication.ApiKeyHeader}) of an administrator, except /api/v1/health and /api/v1/token. " +
                          "The permissions and the scope role of the administrator apply as in the admin UI. Errors are RFC 9457 problem details.",
        };
        document.Servers = [];
        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
        document.Components.SecuritySchemes[BearerSchemeName] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            Description = "A token from POST /api/v1/token.",
        };
        document.Components.SecuritySchemes[ApiKeySchemeName] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.ApiKey,
            In = ParameterLocation.Header,
            Name = ApiAuthentication.ApiKeyHeader,
            Description = "An API key from POST /api/v1/api-keys.",
        };
        document.Security =
        [
            new OpenApiSecurityRequirement { [new OpenApiSecuritySchemeReference(BearerSchemeName, document)] = [] },
            new OpenApiSecurityRequirement { [new OpenApiSecuritySchemeReference(ApiKeySchemeName, document)] = [] },
        ];
        return Task.CompletedTask;
    }
}

/// <summary>The routes without login have no security requirement.</summary>
internal sealed class AnonymousOperationTransformer : IOpenApiOperationTransformer
{
    public Task TransformAsync(OpenApiOperation operation, OpenApiOperationTransformerContext context, CancellationToken cancellationToken)
    {
        if (context.Description.ActionDescriptor.EndpointMetadata.OfType<IAllowAnonymous>().Any())
            operation.Security = [];
        return Task.CompletedTask;
    }
}
