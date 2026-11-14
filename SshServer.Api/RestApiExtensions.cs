using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SshServer.Administration;
using SshServer.Api.ApiKeys;
using SshServer.Api.Authentication;
using SshServer.Api.Dump;
using SshServer.Api.Endpoints;

namespace SshServer.Api;

/// <summary>
/// Registers and maps the REST API v1 (#67). The web host calls <see cref="AddRestApi"/> after the admin authentication
/// (it uses its scoped services: <see cref="CurrentAdmin"/>, <see cref="AdminScopedSettingsRepository"/>, ...) and
/// <see cref="MapRestApi"/> after <c>UseAuthorization</c>. Nothing is mapped until <c>Api:Enabled</c> is true.
/// </summary>
public static class RestApiExtensions
{
    public const string RoutePrefix = "/api/v1";
    public const string OpenApiPath = RoutePrefix + "/openapi.json";
    public const string DocumentName = "v1";

    public static IServiceCollection AddRestApi(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<ApiOptions>().Bind(configuration.GetSection(ApiOptions.SectionName)).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<ApiOptions>, ApiOptionsValidator>());
        if (!ApiOptions.FromConfiguration(configuration).Enabled)
            return services;

        services.TryAddSingleton(TimeProvider.System);
        services.AddDataProtection(); // the host sets the key ring (AddServerDataProtection); it encrypts the token signing key
        services.AddProblemDetails();
        services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

        services.TryAddSingleton<ApiTokenService>();
        services.TryAddSingleton<ITokenSecondFactor, NoTokenSecondFactor>();
        services.TryAddSingleton<ApiKeyService>();
        services.TryAddSingleton<ApiRateLimits>();
        services.TryAddSingleton<StorageMapper>();
        services.TryAddScoped<UserResource>();
        services.TryAddScoped<DumpService>();

        services.AddAuthentication()
            .AddJwtBearer(ApiAuthentication.BearerScheme)
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(ApiAuthentication.ApiKeyScheme, null)
            .AddPolicyScheme(ApiAuthentication.Scheme, "REST API", o => o.ForwardDefaultSelector = ApiAuthentication.SelectScheme);
        services.AddOptions<JwtBearerOptions>(ApiAuthentication.BearerScheme).Configure<ApiTokenService>((o, tokens) =>
        {
            o.MapInboundClaims = false;
            o.TokenValidationParameters = tokens.ValidationParameters();
            o.Events = new JwtBearerEvents { OnTokenValidated = ValidateStampAsync };
        });
        services.AddAuthorization(o => o.AddPolicy(ApiAuthentication.Policy, p => p
            .AddAuthenticationSchemes(ApiAuthentication.Scheme)
            .RequireAuthenticatedUser()));

        services.AddOpenApi(DocumentName, o =>
        {
            o.ShouldInclude = d => d.RelativePath?.StartsWith(RoutePrefix.TrimStart('/'), StringComparison.Ordinal) == true;
            o.AddDocumentTransformer<ApiDocumentTransformer>();
            o.AddOperationTransformer<AnonymousOperationTransformer>();
        });
        return services;
    }

    public static IEndpointRouteBuilder MapRestApi(this IEndpointRouteBuilder endpoints)
    {
        if (!endpoints.ServiceProvider.GetRequiredService<IOptions<ApiOptions>>().Value.Enabled)
            return endpoints;

        var api = endpoints.MapGroup(RoutePrefix)
            .RequireAuthorization(ApiAuthentication.Policy)
            .AddEndpointFilter<ApiExceptionFilter>()
            .AddEndpointFilter<AuthenticationStateFilter>();
        SystemEndpoints.Map(api);
        UserEndpoints.Map(api);
        VirtualFolderEndpoints.Map(api);
        AdminEndpoints.Map(api);
        ApiKeyEndpoints.Map(api);
        MonitoringEndpoints.Map(api);
        WebhookEndpoints.Map(api);
        SettingsEndpoints.Map(api);
        DumpEndpoints.Map(api);
        // An unknown route under /api/v1 is a 404 problem (after the login), not the login page of the UI.
        api.MapFallback("/{**path}", () => ApiResults.NotFound("There is no such route in the REST API v1.")).ExcludeFromDescription();

        endpoints.MapOpenApi(OpenApiPath).RequireAuthorization(ApiAuthentication.Policy);
        return endpoints;
    }

    /// <summary>A token is valid only while the administrator has the same security fields as when it was issued (like the login cookie).</summary>
    private static async Task ValidateStampAsync(TokenValidatedContext context)
    {
        var validator = context.HttpContext.RequestServices.GetRequiredService<AdminSessionValidator>();
        if (context.Principal == null
            || !await validator.IsValidAsync(context.Principal, context.HttpContext.Connection.RemoteIpAddress, context.HttpContext.RequestAborted))
        {
            context.Fail("The administrator changed, is disabled, or may not log in from this address.");
        }
    }
}
