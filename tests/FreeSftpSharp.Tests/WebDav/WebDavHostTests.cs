using System.Net;
using System.Net.Http.Headers;
using System.Text;
using FreeSftpSharp.Tests.WebUi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;
using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.WebDav;

/// <summary>WebDAV in the real web host (FxSshSftpServer): off by default, on with <c>WebDav:Enabled</c>, before the admin login.</summary>
public sealed class WebDavHostTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task By_default_there_is_no_WebDav()
    {
        await using var factory = new AdminUiFactory();
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost/") });

        var response = await client.SendAsync(new HttpRequestMessage(new HttpMethod("PROPFIND"), "/dav/"), Ct);

        Assert.NotEqual(HttpStatusCode.MultiStatus, response.StatusCode);
        Assert.DoesNotContain(response.Headers.WwwAuthenticate, h => h.Scheme == "Basic");
    }

    [Fact]
    public async Task When_enabled_a_user_works_with_Basic_and_the_admin_cookie_is_not_needed()
    {
        await using var factory = new EnabledWebDavFactory();
        var root = Directory.CreateTempSubdirectory("freesftpsharp-webdav-");
        try
        {
            var repository = factory.Services.GetRequiredService<ISettingsRepository>();
            repository.AddUser(new User
            {
                Username = "dav", UserRootDirectory = root.FullName,
                HashedPassword = PasswordHasher.Hash("Correct-Horse-42", PasswordHasher.MinimumIterations),
            });
            var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost/") });

            var anonymous = await client.SendAsync(new HttpRequestMessage(new HttpMethod("PROPFIND"), "/dav/"), Ct);
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("dav:Correct-Horse-42")));
            var put = await client.PutAsync("/dav/hello.txt", new StringContent("hello over WebDAV"), Ct);
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
            Assert.Equal("hello over WebDAV", await File.ReadAllTextAsync(Path.Combine(root.FullName, "hello.txt"), Ct));

            var propfind = new HttpRequestMessage(new HttpMethod("PROPFIND"), "/dav/");
            propfind.Headers.Add("Depth", "1");
            var listing = await client.SendAsync(propfind, Ct);
            Assert.Equal(HttpStatusCode.MultiStatus, listing.StatusCode);
            Assert.Contains("/dav/hello.txt", await listing.Content.ReadAsStringAsync(Ct));

            // The admin UI is unchanged: its pages still need the login.
            var users = await client.GetAsync("/users", Ct);
            Assert.True(users.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found or HttpStatusCode.Unauthorized, users.StatusCode.ToString());
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    private sealed class EnabledWebDavFactory : AdminUiFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.UseSetting("WebDav:Enabled", "true");
            // TestServer has no client address; Kestrel always has one.
            builder.ConfigureServices(services => services.AddSingleton<IStartupFilter, LoopbackClientFilter>());
        }
    }

    private sealed class LoopbackClientFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, nextMiddleware) =>
            {
                context.Connection.RemoteIpAddress ??= IPAddress.Loopback;
                return nextMiddleware(context);
            });
            next(app);
        };
    }
}
