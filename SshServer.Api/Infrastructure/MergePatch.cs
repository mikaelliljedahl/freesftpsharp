using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;

namespace SshServer.Api;

/// <summary>
/// JSON merge patch (RFC 7396) for the PATCH routes: the patch is merged into the write model of the stored object
/// (members of the patch replace those of the object, <c>null</c> removes one, objects are merged), and the result is
/// saved like a PUT. A secret that is not in the patch keeps its stored value, because the write model never has it.
/// Member names are compared exactly, as in the RFC: the API uses camelCase names.
/// </summary>
internal static class MergePatch
{
    /// <summary>
    /// The patch of the request body (application/merge-patch+json or application/json). It is read here and not bound
    /// as a parameter, so the OpenAPI document shows the write model of the route as the body.
    /// </summary>
    public static async Task<JsonObject> ReadAsync(HttpRequest request)
    {
        if (!request.HasJsonContentType())
            throw new ApiValidationException("", "The body must be a JSON merge patch (application/merge-patch+json).");
        try
        {
            return await JsonNode.ParseAsync(request.Body, cancellationToken: request.HttpContext.RequestAborted) as JsonObject
                   ?? throw new ApiValidationException("", "The patch must be a JSON object.");
        }
        catch (JsonException)
        {
            throw new ApiValidationException("", "The body is not valid JSON.");
        }
    }

    public static T Apply<T>(T current, JsonObject patch, JsonSerializerOptions options)
    {
        var target = JsonSerializer.SerializeToNode(current, options) as JsonObject ?? new JsonObject();
        Merge(target, patch);
        return target.Deserialize<T>(options) ?? throw new ApiValidationException("", "The patch must be a JSON object.");
    }

    private static void Merge(JsonObject target, JsonObject patch)
    {
        foreach (var (name, value) in patch.ToList())
        {
            var key = name;
            if (value is null)
            {
                target.Remove(key);
            }
            else if (value is JsonObject patchObject && target[key] is JsonObject targetObject)
            {
                Merge(targetObject, patchObject);
            }
            else
            {
                target.Remove(key);
                target[key] = value.DeepClone();
            }
        }
    }
}
