using System.Net;
using System.Text;
using System.Xml.Linq;
using FreeSftpSharp.Tests.Storage;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.WebDav;

/// <summary>
/// The WebDAV methods (RFC 4918), litmus style: each test sends the requests of one litmus case (basic, copymove, props,
/// locks) to the in-memory server and checks the status codes and the storage.
/// </summary>
public sealed class WebDavMethodTests : IAsyncLifetime
{
    private static readonly XNamespace D = "DAV:";
    private WebDavTestHost _host = null!;
    private HttpClient _client = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await WebDavTestHost.StartAsync();
        _host.AddUser("alice");
        _client = _host.Client("alice");
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private InMemoryFileSystem Storage => _host.StorageOf("alice");

    private static async Task<string> TextAsync(IFileSystem fs, string path)
    {
        await using var handle = await fs.OpenAsync(path, FileOpenFlags.Read, null, CancellationToken.None);
        var buffer = new byte[64 * 1024];
        var read = await handle.ReadAsync(0, buffer, CancellationToken.None);
        return Encoding.UTF8.GetString(buffer, 0, read);
    }

    private async Task<XDocument> MultistatusAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.MultiStatus, response.StatusCode);
        return XDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    // ---- basic ----

    [Fact]
    public async Task Options_AnnouncesClass1And2AndTheMethods()
    {
        var response = await _client.SendAsync("OPTIONS", "/dav/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("1, 2", string.Join(",", response.Headers.GetValues("DAV")));
        var allow = string.Join(",", response.Content.Headers.Allow);
        foreach (var method in new[] { "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "PUT", "DELETE" })
            Assert.Contains(method, allow);
    }

    [Fact]
    public async Task PutGetHead_RoundTripsTheContent()
    {
        var put = await _client.PutAsync("/dav/res", "This is a test file.");
        Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        Assert.NotNull(put.Headers.ETag);

        var get = await _client.GetAsync("/dav/res", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        Assert.Equal("This is a test file.", await get.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal(put.Headers.ETag, get.Headers.ETag);
        Assert.NotNull(get.Content.Headers.LastModified);

        var head = await _client.SendAsync("HEAD", "/dav/res");
        Assert.Equal(HttpStatusCode.OK, head.StatusCode);
        Assert.Equal(20, head.Content.Headers.ContentLength);

        var replace = await _client.PutAsync("/dav/res", "Replaced.");
        Assert.Equal(HttpStatusCode.NoContent, replace.StatusCode);
        Assert.Equal("Replaced.", await TextAsync(Storage, "/res"));
    }

    [Fact]
    public async Task Put_WithoutParent_Is409_AndOnACollection_Is405()
    {
        Assert.Equal(HttpStatusCode.Conflict, (await _client.PutAsync("/dav/missing/res", "x")).StatusCode);
        await Storage.CreateDirectoryAsync("/coll", CancellationToken.None);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await _client.PutAsync("/dav/coll", "x")).StatusCode);
    }

    [Fact]
    public async Task Put_WithIfNoneMatchStar_RefusesToReplace()
    {
        await _client.PutAsync("/dav/res", "one");
        var response = await _client.PutAsync("/dav/res", "two", ("If-None-Match", "*"));
        Assert.Equal(HttpStatusCode.PreconditionFailed, response.StatusCode);
        Assert.Equal("one", await TextAsync(Storage, "/res"));
    }

    [Fact]
    public async Task Get_Range_And_Conditional()
    {
        var put = await _client.PutAsync("/dav/range.txt", "0123456789");

        var range = await _client.SendAsync("GET", "/dav/range.txt", null, ("Range", "bytes=2-5"));
        Assert.Equal(HttpStatusCode.PartialContent, range.StatusCode);
        Assert.Equal("2345", await range.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal("bytes 2-5/10", range.Content.Headers.ContentRange?.ToString());

        var suffix = await _client.SendAsync("GET", "/dav/range.txt", null, ("Range", "bytes=-3"));
        Assert.Equal("789", await suffix.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        var outside = await _client.SendAsync("GET", "/dav/range.txt", null, ("Range", "bytes=20-"));
        Assert.Equal(HttpStatusCode.RequestedRangeNotSatisfiable, outside.StatusCode);

        var notModified = await _client.SendAsync("GET", "/dav/range.txt", null, ("If-None-Match", put.Headers.ETag!.ToString()));
        Assert.Equal(HttpStatusCode.NotModified, notModified.StatusCode);

        var ifMatch = await _client.SendAsync("GET", "/dav/range.txt", null, ("If-Match", "\"other\""));
        Assert.Equal(HttpStatusCode.PreconditionFailed, ifMatch.StatusCode);
    }

    [Fact]
    public async Task Mkcol_CreatesACollection_AndKnowsTheErrors()
    {
        Assert.Equal(HttpStatusCode.Created, (await _client.SendAsync("MKCOL", "/dav/coll/")).StatusCode);
        Assert.True((await Storage.StatAsync("/coll", true, CancellationToken.None))!.IsDirectory);

        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await _client.SendAsync("MKCOL", "/dav/coll/")).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await _client.SendAsync("MKCOL", "/dav/a/b/")).StatusCode);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await _client.SendAsync("MKCOL", "/dav/withbody/", "<x/>")).StatusCode);
    }

    [Fact]
    public async Task Delete_RemovesAFileAndACollectionWithItsMembers()
    {
        await _client.PutAsync("/dav/res", "x");
        await _client.SendAsync("MKCOL", "/dav/coll/");
        await _client.SendAsync("MKCOL", "/dav/coll/sub/");
        await _client.PutAsync("/dav/coll/sub/file", "y");

        Assert.Equal(HttpStatusCode.NoContent, (await _client.DeleteAsync("/dav/res", TestContext.Current.CancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _client.DeleteAsync("/dav/coll/", TestContext.Current.CancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _client.DeleteAsync("/dav/coll/", TestContext.Current.CancellationToken)).StatusCode);
        Assert.Null(await Storage.StatAsync("/coll", true, CancellationToken.None));
        Assert.Equal(HttpStatusCode.Forbidden, (await _client.DeleteAsync("/dav/", TestContext.Current.CancellationToken)).StatusCode);
    }

    [Fact]
    public async Task Get_OfACollection_IsAnHtmlListing()
    {
        await _client.PutAsync("/dav/a <b>.txt", "x");
        var response = await _client.GetAsync("/dav/", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("a &lt;b&gt;.txt", html);
        Assert.Contains("/dav/a%20%3Cb%3E.txt", html);
    }

    // ---- props ----

    [Fact]
    public async Task Propfind_Depth0_GivesTheResourceItself()
    {
        var response = await _client.SendAsync("PROPFIND", "/dav/", null, ("Depth", "0"));
        var xml = await MultistatusAsync(response);

        var only = Assert.Single(xml.Root!.Elements(D + "response"));
        Assert.Equal("/dav/", only.Element(D + "href")!.Value);
        Assert.NotNull(only.Descendants(D + "resourcetype").Single().Element(D + "collection"));
        Assert.Contains("200 OK", only.Descendants(D + "status").First().Value);
    }

    [Fact]
    public async Task Propfind_Depth1_ListsTheMembersWithTheirProperties()
    {
        await _client.PutAsync("/dav/file one.txt", "12345");
        await _client.SendAsync("MKCOL", "/dav/sub/");

        var xml = await MultistatusAsync(await _client.SendAsync("PROPFIND", "/dav/", null, ("Depth", "1")));
        var hrefs = xml.Descendants(D + "href").Select(h => h.Value).ToList();
        Assert.Equal(["/dav/", "/dav/file%20one.txt", "/dav/sub/"], hrefs);

        var file = xml.Root!.Elements(D + "response").Single(r => r.Element(D + "href")!.Value == "/dav/file%20one.txt");
        Assert.Equal("5", file.Descendants(D + "getcontentlength").Single().Value);
        Assert.Equal("text/plain", file.Descendants(D + "getcontenttype").Single().Value);
        Assert.False(string.IsNullOrEmpty(file.Descendants(D + "getetag").Single().Value));
        Assert.True(DateTime.TryParse(file.Descendants(D + "getlastmodified").Single().Value, out _));
        Assert.NotNull(file.Descendants(D + "supportedlock").Single().Element(D + "lockentry"));
    }

    [Fact]
    public async Task Propfind_DepthInfinity_IsRefused()
    {
        var response = await _client.SendAsync("PROPFIND", "/dav/", null, ("Depth", "infinity"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("propfind-finite-depth", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Propfind_NamedProperties_UnknownOnesAre404()
    {
        await _client.PutAsync("/dav/res", "x");
        const string body = """
            <?xml version="1.0" encoding="utf-8"?>
            <propfind xmlns="DAV:" xmlns:z="http://example.com/neon/litmus/"><prop><getcontentlength/><z:foo/></prop></propfind>
            """;
        var xml = await MultistatusAsync(await _client.SendAsync("PROPFIND", "/dav/res", body, ("Depth", "0")));

        var propstats = xml.Descendants(D + "propstat").ToList();
        Assert.Equal(2, propstats.Count);
        Assert.Contains(propstats, p => p.Element(D + "status")!.Value.Contains("200") && p.Descendants(D + "getcontentlength").Any());
        Assert.Contains(propstats, p => p.Element(D + "status")!.Value.Contains("404")
            && p.Descendants(XNamespace.Get("http://example.com/neon/litmus/") + "foo").Any());
    }

    [Fact]
    public async Task Propfind_Propname_GivesNamesWithoutValues()
    {
        await _client.PutAsync("/dav/res", "x");
        const string body = """<?xml version="1.0"?><propfind xmlns="DAV:"><propname/></propfind>""";
        var xml = await MultistatusAsync(await _client.SendAsync("PROPFIND", "/dav/res", body, ("Depth", "0")));
        var length = xml.Descendants(D + "getcontentlength").Single();
        Assert.Equal("", length.Value);
    }

    [Fact]
    public async Task Propfind_MissingResource_Is404_AndBadXml_Is400()
    {
        Assert.Equal(HttpStatusCode.NotFound, (await _client.SendAsync("PROPFIND", "/dav/nothing", null, ("Depth", "0"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.SendAsync("PROPFIND", "/dav/", "<propfind", ("Depth", "0"))).StatusCode);
    }

    [Fact]
    public async Task Proppatch_SetsTheLastModifiedTime()
    {
        await _client.PutAsync("/dav/res", "x");
        const string body = """
            <?xml version="1.0" encoding="utf-8"?>
            <D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><D:getlastmodified>Mon, 12 Jan 1998 09:25:56 GMT</D:getlastmodified></D:prop></D:set></D:propertyupdate>
            """;
        var xml = await MultistatusAsync(await _client.SendAsync("PROPPATCH", "/dav/res", body));

        Assert.Contains("200", xml.Descendants(D + "status").Single().Value);
        var entry = await Storage.StatAsync("/res", true, CancellationToken.None);
        Assert.Equal(new DateTime(1998, 1, 12, 9, 25, 56, DateTimeKind.Utc), entry!.LastWriteTimeUtc);
    }

    [Fact]
    public async Task Proppatch_Win32Times_AreAcceptedAsWindowsSendsThem()
    {
        await _client.PutAsync("/dav/res", "x");
        const string body = """
            <?xml version="1.0" encoding="utf-8"?>
            <D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:schemas-microsoft-com:"><D:set><D:prop>
            <Z:Win32CreationTime>Thu, 01 Oct 2026 10:00:00 GMT</Z:Win32CreationTime>
            <Z:Win32LastAccessTime>Thu, 01 Oct 2026 10:00:00 GMT</Z:Win32LastAccessTime>
            <Z:Win32LastModifiedTime>Thu, 01 Oct 2026 10:00:00 GMT</Z:Win32LastModifiedTime>
            <Z:Win32FileAttributes>00000020</Z:Win32FileAttributes>
            </D:prop></D:set></D:propertyupdate>
            """;
        var xml = await MultistatusAsync(await _client.SendAsync("PROPPATCH", "/dav/res", body));
        Assert.All(xml.Descendants(D + "status"), s => Assert.Contains("200", s.Value));
        Assert.Equal(new DateTime(2026, 10, 1, 10, 0, 0, DateTimeKind.Utc), (await Storage.StatAsync("/res", true, CancellationToken.None))!.LastWriteTimeUtc);
    }

    [Fact]
    public async Task Proppatch_DeadProperty_Is403_AndTheOthersFailWith424()
    {
        await _client.PutAsync("/dav/res", "x");
        var before = (await Storage.StatAsync("/res", true, CancellationToken.None))!.LastWriteTimeUtc;
        const string body = """
            <?xml version="1.0" encoding="utf-8"?>
            <D:propertyupdate xmlns:D="DAV:" xmlns:Z="http://example.com/neon/litmus/"><D:set><D:prop>
            <D:getlastmodified>Mon, 12 Jan 1998 09:25:56 GMT</D:getlastmodified><Z:prop0>value0</Z:prop0>
            </D:prop></D:set></D:propertyupdate>
            """;
        var xml = await MultistatusAsync(await _client.SendAsync("PROPPATCH", "/dav/res", body));

        var statuses = xml.Descendants(D + "propstat").ToDictionary(p => p.Element(D + "prop")!.Elements().Single().Name.LocalName,
            p => p.Element(D + "status")!.Value);
        Assert.Contains("403", statuses["prop0"]);
        Assert.Contains("424", statuses["getlastmodified"]);
        Assert.Equal(before, (await Storage.StatAsync("/res", true, CancellationToken.None))!.LastWriteTimeUtc);
    }

    // ---- copymove ----

    [Fact]
    public async Task Copy_File_WithOverwrite()
    {
        await _client.PutAsync("/dav/src", "source");
        await _client.PutAsync("/dav/dest", "old");

        var refused = await _client.SendAsync("COPY", "/dav/src", null, ("Destination", "https://localhost/dav/dest"), ("Overwrite", "F"));
        Assert.Equal(HttpStatusCode.PreconditionFailed, refused.StatusCode);
        Assert.Equal("old", await TextAsync(Storage, "/dest"));

        var replaced = await _client.SendAsync("COPY", "/dav/src", null, ("Destination", "https://localhost/dav/dest"), ("Overwrite", "T"));
        Assert.Equal(HttpStatusCode.NoContent, replaced.StatusCode);
        Assert.Equal("source", await TextAsync(Storage, "/dest"));

        var created = await _client.SendAsync("COPY", "/dav/src", null, ("Destination", "/dav/new"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal("source", await TextAsync(Storage, "/src"));
        Assert.Equal("source", await TextAsync(Storage, "/new"));
    }

    [Fact]
    public async Task Copy_Collection_DepthInfinityCopiesTheMembers_Depth0OnlyTheCollection()
    {
        await _client.SendAsync("MKCOL", "/dav/ccsrc/");
        await _client.PutAsync("/dav/ccsrc/foo", "1");
        await _client.SendAsync("MKCOL", "/dav/ccsrc/subcoll/");
        await _client.PutAsync("/dav/ccsrc/subcoll/bar", "2");

        Assert.Equal(HttpStatusCode.Created, (await _client.SendAsync("COPY", "/dav/ccsrc/", null, ("Destination", "/dav/ccdest/"))).StatusCode);
        Assert.Equal("2", await TextAsync(Storage, "/ccdest/subcoll/bar"));

        Assert.Equal(HttpStatusCode.Created,
            (await _client.SendAsync("COPY", "/dav/ccsrc/", null, ("Destination", "/dav/shallow/"), ("Depth", "0"))).StatusCode);
        Assert.True((await Storage.StatAsync("/shallow", true, CancellationToken.None))!.IsDirectory);
        Assert.Null(await Storage.StatAsync("/shallow/foo", true, CancellationToken.None));
    }

    [Fact]
    public async Task Move_File_AndOntoAnExistingFile()
    {
        await _client.PutAsync("/dav/move", "moved");
        await _client.PutAsync("/dav/target", "old");

        Assert.Equal(HttpStatusCode.PreconditionFailed,
            (await _client.SendAsync("MOVE", "/dav/move", null, ("Destination", "/dav/target"), ("Overwrite", "F"))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _client.SendAsync("MOVE", "/dav/move", null, ("Destination", "/dav/target"))).StatusCode);
        Assert.Null(await Storage.StatAsync("/move", true, CancellationToken.None));
        Assert.Equal("moved", await TextAsync(Storage, "/target"));

        Assert.Equal(HttpStatusCode.Created, (await _client.SendAsync("MOVE", "/dav/target", null, ("Destination", "/dav/renamed"))).StatusCode);
        Assert.Equal("moved", await TextAsync(Storage, "/renamed"));
    }

    [Fact]
    public async Task Move_Collection_OntoACollection_ReplacesIt()
    {
        await _client.SendAsync("MKCOL", "/dav/a/");
        await _client.PutAsync("/dav/a/x", "1");
        await _client.SendAsync("MKCOL", "/dav/b/");
        await _client.PutAsync("/dav/b/old", "2");

        Assert.Equal(HttpStatusCode.NoContent, (await _client.SendAsync("MOVE", "/dav/a/", null, ("Destination", "/dav/b/"))).StatusCode);
        Assert.Equal("1", await TextAsync(Storage, "/b/x"));
        Assert.Null(await Storage.StatAsync("/b/old", true, CancellationToken.None));
        Assert.Null(await Storage.StatAsync("/a", true, CancellationToken.None));
    }

    [Fact]
    public async Task CopyMove_ErrorCases()
    {
        await _client.SendAsync("MKCOL", "/dav/coll/");
        await _client.PutAsync("/dav/file", "x");

        Assert.Equal(HttpStatusCode.Forbidden, (await _client.SendAsync("MOVE", "/dav/coll/", null, ("Destination", "/dav/coll/inner/"))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await _client.SendAsync("COPY", "/dav/file", null, ("Destination", "/dav/file"))).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await _client.SendAsync("COPY", "/dav/file", null, ("Destination", "/dav/no/such/file"))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _client.SendAsync("MOVE", "/dav/nothing", null, ("Destination", "/dav/x"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.SendAsync("MOVE", "/dav/file")).StatusCode);
        Assert.Equal(HttpStatusCode.BadGateway,
            (await _client.SendAsync("COPY", "/dav/file", null, ("Destination", "https://elsewhere.example/dav/file"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadGateway, (await _client.SendAsync("COPY", "/dav/file", null, ("Destination", "/other/file"))).StatusCode);
    }

    // ---- locks ----

    private async Task<string> LockAsync(string url, string body = Dav.LockBody, params (string, string)[] headers)
    {
        var response = await _client.SendAsync("LOCK", url, body, headers);
        Assert.True(response.StatusCode is HttpStatusCode.OK or HttpStatusCode.Created, $"LOCK gave {response.StatusCode}");
        var token = response.Headers.GetValues("Lock-Token").Single();
        Assert.StartsWith("<urn:uuid:", token);
        var xml = XDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal(token.Trim('<', '>'), xml.Descendants(D + "locktoken").Single().Element(D + "href")!.Value);
        Assert.Equal("litmus test suite", xml.Descendants(D + "owner").SingleOrDefault()?.Value ?? "litmus test suite");
        return token;
    }

    [Fact]
    public async Task Lock_Exclusive_BlocksOtherWritesUntilTheTokenIsSubmitted()
    {
        await _client.PutAsync("/dav/lockme", "v1");
        var token = await LockAsync("/dav/lockme");

        Assert.Equal((HttpStatusCode)423, (await _client.PutAsync("/dav/lockme", "v2")).StatusCode);
        Assert.Equal((HttpStatusCode)423, (await _client.DeleteAsync("/dav/lockme", TestContext.Current.CancellationToken)).StatusCode);
        Assert.Equal((HttpStatusCode)423, (await _client.SendAsync("MOVE", "/dav/lockme", null, ("Destination", "/dav/moved"))).StatusCode);
        Assert.Equal((HttpStatusCode)423, (await _client.SendAsync("LOCK", "/dav/lockme", Dav.LockBody)).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await _client.PutAsync("/dav/lockme", "v2", ("If", $"({token})"))).StatusCode);
        Assert.Equal("v2", await TextAsync(Storage, "/lockme"));

        // A copy of a locked resource is allowed; the lock does not go with it.
        Assert.Equal(HttpStatusCode.Created, (await _client.SendAsync("COPY", "/dav/lockme", null, ("Destination", "/dav/copy"))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _client.PutAsync("/dav/copy", "free")).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await _client.SendAsync("UNLOCK", "/dav/lockme", null, ("Lock-Token", token))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _client.PutAsync("/dav/lockme", "v3")).StatusCode);
    }

    [Fact]
    public async Task Lock_DiscoveryShowsTheLock_AndUnlockNeedsTheRightToken()
    {
        await _client.PutAsync("/dav/res", "x");
        var token = await LockAsync("/dav/res", Dav.LockBody, ("Timeout", "Second-3600"));

        const string body = """<?xml version="1.0"?><propfind xmlns="DAV:"><prop><lockdiscovery/></prop></propfind>""";
        var xml = await MultistatusAsync(await _client.SendAsync("PROPFIND", "/dav/res", body, ("Depth", "0")));
        var active = xml.Descendants(D + "activelock").Single();
        Assert.NotNull(active.Element(D + "lockscope")!.Element(D + "exclusive"));
        Assert.Equal("Second-3600", active.Element(D + "timeout")!.Value);

        var wrong = await _client.SendAsync("UNLOCK", "/dav/res", null, ("Lock-Token", "<urn:uuid:00000000-0000-0000-0000-000000000000>"));
        Assert.Equal(HttpStatusCode.Conflict, wrong.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _client.SendAsync("UNLOCK", "/dav/res", null, ("Lock-Token", token))).StatusCode);
    }

    [Fact]
    public async Task Lock_Conditions_BadTokenOrEtag_Is412_AndNoLockIsRefused()
    {
        await _client.PutAsync("/dav/res", "x");
        var token = await LockAsync("/dav/res");

        Assert.Equal(HttpStatusCode.PreconditionFailed, (await _client.PutAsync("/dav/res", "y", ("If", $"({token} [\"bad-etag\"])"))).StatusCode);
        Assert.Equal(HttpStatusCode.PreconditionFailed, (await _client.PutAsync("/dav/res", "y", ("If", "(<DAV:no-lock>)"))).StatusCode);
        // A list that is true without the token: the header passes, but the lock still needs its token.
        Assert.Equal((HttpStatusCode)423,
            (await _client.PutAsync("/dav/res", "y", ("If", "(<urn:uuid:corrupt>) (Not <DAV:no-lock>)"))).StatusCode);
        var etag = (await _client.SendAsync("HEAD", "/dav/res")).Headers.ETag!.ToString();
        Assert.Equal(HttpStatusCode.NoContent, (await _client.PutAsync("/dav/res", "y", ("If", $"<https://localhost/dav/res> ({token} [{etag}])"))).StatusCode);
    }

    [Fact]
    public async Task Lock_Refresh_And_Timeout()
    {
        await _client.PutAsync("/dav/res", "x");
        var token = await LockAsync("/dav/res", Dav.LockBody, ("Timeout", "Second-100"));

        _host.Time.Advance(TimeSpan.FromSeconds(80));
        var refresh = await _client.SendAsync("LOCK", "/dav/res", null, ("If", $"({token})"), ("Timeout", "Second-100"));
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);

        _host.Time.Advance(TimeSpan.FromSeconds(80));
        Assert.Equal((HttpStatusCode)423, (await _client.PutAsync("/dav/res", "y")).StatusCode);

        _host.Time.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(HttpStatusCode.NoContent, (await _client.PutAsync("/dav/res", "y")).StatusCode);
    }

    [Fact]
    public async Task Lock_Shared_AllowsAnotherSharedLockButNoExclusive()
    {
        await _client.PutAsync("/dav/res", "x");
        await LockAsync("/dav/res", Dav.SharedLockBody);
        await LockAsync("/dav/res", Dav.SharedLockBody);
        Assert.Equal((HttpStatusCode)423, (await _client.SendAsync("LOCK", "/dav/res", Dav.LockBody)).StatusCode);
    }

    [Fact]
    public async Task Lock_UnmappedUrl_CreatesAnEmptyResource()
    {
        var token = await LockAsync("/dav/newfile");
        var entry = await Storage.StatAsync("/newfile", true, CancellationToken.None);
        Assert.Equal(0, entry!.Size);
        Assert.Equal(HttpStatusCode.NoContent, (await _client.PutAsync("/dav/newfile", "content", ("If", $"({token})"))).StatusCode);
    }

    [Fact]
    public async Task Lock_CollectionDepthInfinity_ProtectsNewAndExistingMembers()
    {
        await _client.SendAsync("MKCOL", "/dav/coll/");
        await _client.PutAsync("/dav/coll/member", "x");
        var token = await LockAsync("/dav/coll/", Dav.LockBody, ("Depth", "infinity"));

        Assert.Equal((HttpStatusCode)423, (await _client.PutAsync("/dav/coll/member", "y")).StatusCode);
        Assert.Equal((HttpStatusCode)423, (await _client.PutAsync("/dav/coll/new", "y")).StatusCode);
        Assert.Equal((HttpStatusCode)423, (await _client.SendAsync("MKCOL", "/dav/coll/sub/")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await _client.PutAsync("/dav/coll/new", "y", ("If", $"({token})"))).StatusCode);

        // A lock on a member conflicts with the lock of the collection.
        Assert.Equal((HttpStatusCode)423, (await _client.SendAsync("LOCK", "/dav/coll/member", Dav.LockBody)).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent,
            (await _client.SendAsync("DELETE", "/dav/coll/", null, ("If", $"({token})"))).StatusCode);
        // The lock went with the collection.
        Assert.Equal(HttpStatusCode.Created, (await _client.SendAsync("MKCOL", "/dav/coll/")).StatusCode);
    }

    // ---- paths ----

    [Theory]
    [InlineData("/dav/%2e%2e/secret")]
    [InlineData("/dav/a/%2E%2E/%2E%2E/secret")]
    [InlineData("/dav/a%2Fb")]
    [InlineData("/dav/a%5Cb")]
    [InlineData("/dav/a%00b")]
    public async Task Traversal_IsRefused(string url)
    {
        // HttpClient and TestServer clean the URL; Kestrel gives the raw target as the client sent it.
        var response = await _client.SendAsync("GET", "/dav/x", null, (WebDavTestHost.RawTargetHeader, url));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Traversal_InTheDestination_IsRefused()
    {
        await _client.PutAsync("/dav/file", "x");
        var response = await _client.SendAsync("COPY", "/dav/file", null, ("Destination", "https://localhost/dav/a/../../outside"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task UnicodeNames_RoundTrip()
    {
        Assert.Equal(HttpStatusCode.Created, (await _client.PutAsync("/dav/r%C3%A4ksm%C3%B6rg%C3%A5s.txt", "x")).StatusCode);
        Assert.NotNull(await Storage.StatAsync("/räksmörgås.txt", true, CancellationToken.None));
        var xml = await MultistatusAsync(await _client.SendAsync("PROPFIND", "/dav/", null, ("Depth", "1")));
        Assert.Contains(xml.Descendants(D + "href"), h => h.Value == "/dav/r%C3%A4ksm%C3%B6rg%C3%A5s.txt");
    }
}
