using System.Net;
using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using FreeSftpSharp.Tests.WebUi;

namespace FreeSftpSharp.Tests.Api;

/// <summary>
/// The OpenAPI document of the REST API describes every route, and the committed docs/openapi.json is the same as the
/// generated one, so a change of the API is visible in the diff of a pull request. After an intended change, run the
/// tests with FREESFTPSHARP_UPDATE_OPENAPI=1 to write the new document.
/// </summary>
[Collection(AdminUiCollection.Name)]
public sealed class OpenApiDocumentTests : IClassFixture<ApiFactory>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly ApiFactory _factory;

    public OpenApiDocumentTests(ApiFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task The_document_has_every_resource_and_both_security_schemes()
    {
        var document = await GetDocumentAsync();

        var paths = document["paths"]!.AsObject().Select(p => p.Key).ToList();
        foreach (var path in new[]
                 {
                     "/api/v1/token", "/api/v1/health", "/api/v1/status", "/api/v1/users", "/api/v1/users/{username}",
                     "/api/v1/users/{username}/public-keys", "/api/v1/virtual-folders", "/api/v1/virtual-folders/{id}", "/api/v1/admins",
                     "/api/v1/roles", "/api/v1/api-keys", "/api/v1/connections", "/api/v1/audit", "/api/v1/webhooks", "/api/v1/ip-bans",
                     "/api/v1/settings", "/api/v1/storage-providers", "/api/v1/dump", "/api/v1/load",
                 })
        {
            Assert.Contains(path, paths);
        }
        Assert.DoesNotContain(paths, p => !p.StartsWith("/api/v1/", StringComparison.Ordinal));
        var schemes = document["components"]!["securitySchemes"]!.AsObject();
        Assert.True(schemes.ContainsKey("bearer"));
        Assert.Equal("X-API-Key", schemes["apiKey"]!["name"]!.GetValue<string>());
        Assert.Empty(document["paths"]!["/api/v1/health"]!["get"]!["security"]!.AsArray());
    }

    [Fact]
    public async Task The_committed_document_is_the_generated_one()
    {
        var generated = (await GetDocumentAsync()).ToJsonString(new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        }).ReplaceLineEndings("\n") + "\n";
        var path = Path.Combine(RepositoryRoot(), "docs", "openapi.json");

        if (Environment.GetEnvironmentVariable("FREESFTPSHARP_UPDATE_OPENAPI") == "1")
            await File.WriteAllTextAsync(path, generated, Ct);

        Assert.True(File.Exists(path), "docs/openapi.json is missing: run the tests with FREESFTPSHARP_UPDATE_OPENAPI=1.");
        var committed = (await File.ReadAllTextAsync(path, Ct)).ReplaceLineEndings("\n");
        Assert.True(committed == generated,
            "docs/openapi.json differs from the generated OpenAPI document. Run the tests with FREESFTPSHARP_UPDATE_OPENAPI=1 and commit the file.");
    }

    private async Task<JsonObject> GetDocumentAsync()
    {
        using var client = await _factory.SuperAdminAsync();
        var response = await client.GetAsync("/api/v1/openapi.json", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.JsonAsync();
    }

    private static string RepositoryRoot([CallerFilePath] string file = "")
    {
        var directory = new DirectoryInfo(Path.GetDirectoryName(file)!);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "FreeSftpSharp.sln")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("The repository root was not found.");
    }
}
