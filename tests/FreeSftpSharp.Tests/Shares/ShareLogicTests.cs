using FxSshSftpServer.WebClient;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Shares;

namespace FreeSftpSharp.Tests.Shares;

/// <summary>The id of a share link (#70): 160 random bits, base64url, and the check of a text before any lookup.</summary>
public sealed class ShareIdTests
{
    [Fact]
    public void A_new_id_is_160_bits_in_url_safe_base64_without_padding()
    {
        var id = ShareId.New();

        Assert.Equal(ShareId.Length, id.Length);
        Assert.Matches("^[A-Za-z0-9_-]{27}$", id);
        Assert.True(ShareId.IsWellFormed(id));
        Assert.Equal(ShareId.Bytes, System.Buffers.Text.Base64Url.DecodeFromChars(id).Length);
    }

    [Fact]
    public void Ids_do_not_repeat()
    {
        var ids = Enumerable.Range(0, 10_000).Select(_ => ShareId.New()).ToHashSet(StringComparer.Ordinal);

        Assert.Equal(10_000, ids.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("short")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAA")] // 26
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAA")] // 28
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAA+")] // standard base64
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAA/")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAA..")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAA%")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAÄ")]
    public void Other_texts_are_not_ids(string? text)
    {
        Assert.False(ShareId.IsWellFormed(text));
    }
}

/// <summary>The containment check of the share paths (#70): a request may use only the shared paths and what is below.</summary>
public sealed class SharePathsTests
{
    private static readonly string[] Roots = ["/out/reports", "/docs/a.pdf"];

    [Theory]
    [InlineData("/out/reports")]
    [InlineData("/out/reports/")]
    [InlineData("/out/reports/2026/q1.csv")]
    [InlineData("out/reports/x")]
    [InlineData("/out/./reports/x")]
    [InlineData("/out/reports/2026/../q1.csv")]
    [InlineData("\\out\\reports\\x")]
    [InlineData("/docs/a.pdf")]
    public void Paths_in_the_share_are_contained(string path)
    {
        Assert.True(SharePaths.Contains(Roots, path, caseInsensitivePaths: false));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("/")]
    [InlineData("/out")]
    [InlineData("/out/reportsX")]
    [InlineData("/out/reports-old/x")]
    [InlineData("/out/reports/../secret.txt")]
    [InlineData("/out/reports/../../etc/passwd")]
    [InlineData("/out/reports/..")]
    [InlineData("/docs")]
    [InlineData("/docs/a.pdf.bak")]
    [InlineData("/docs/b.pdf")]
    [InlineData("/OUT/REPORTS/x")]
    public void Other_paths_are_not_contained(string? path)
    {
        Assert.False(SharePaths.Contains(Roots, path, caseInsensitivePaths: false));
    }

    [Theory]
    [InlineData("/OUT/Reports/x", true)]
    [InlineData("/out/reports./x", true)] // the same directory on Windows
    [InlineData("/out/reportsx", false)]
    public void A_case_insensitive_storage_compares_like_the_storage(string path, bool contained)
    {
        Assert.Equal(contained, SharePaths.Contains(Roots, path, caseInsensitivePaths: true));
    }

    [Fact]
    public void A_share_of_the_root_contains_nothing()
    {
        Assert.False(SharePaths.Contains(["/"], "/anything", false));
        Assert.False(SharePaths.Contains(["/../"], "/anything", false));
    }

    [Fact]
    public void RootOf_finds_the_shared_path()
    {
        Assert.Equal("/out/reports", SharePaths.RootOf(Roots, "/out/reports/a/b", false));
        Assert.Null(SharePaths.RootOf(Roots, "/out", false));
    }

    [Fact]
    public void Normalize_removes_duplicates_and_refuses_the_root_and_nothing()
    {
        var errors = new List<string>();
        var paths = SharePaths.Normalize(["/a/", "a", "  /b/../c ", "", null], errors);
        Assert.Equal(["/a", "/c"], paths);
        Assert.Empty(errors);

        errors.Clear();
        SharePaths.Normalize(["/x/.."], errors);
        Assert.Contains(errors, e => e.Contains("whole home folder", StringComparison.Ordinal));

        errors.Clear();
        SharePaths.Normalize([], errors);
        Assert.Single(errors);

        errors.Clear();
        SharePaths.Normalize(Enumerable.Range(0, ShareRules.MaxPaths + 1).Select(i => "/p" + i), errors);
        Assert.Single(errors);
    }
}

/// <summary>The rules of a share without the storage (#70): expiry, uses and the permissions of the scope.</summary>
public sealed class ShareRulesTests
{
    private static readonly DateTime Now = new(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void A_share_is_usable_until_it_expires_and_until_it_is_used_up()
    {
        Assert.True(ShareRules.IsUsable(new Share(), Now));
        Assert.True(ShareRules.IsUsable(new Share { ExpiresAt = Now.AddSeconds(1) }, Now));
        Assert.False(ShareRules.IsUsable(new Share { ExpiresAt = Now }, Now));
        Assert.False(ShareRules.IsUsable(new Share { ExpiresAt = Now.AddDays(-1) }, Now));
        Assert.True(ShareRules.IsUsable(new Share { MaxUses = 2, UsedCount = 1 }, Now));
        Assert.False(ShareRules.IsUsable(new Share { MaxUses = 2, UsedCount = 2 }, Now));
        Assert.True(ShareRules.IsUsable(new Share { MaxUses = 0, UsedCount = 1000 }, Now));
    }

    [Fact]
    public void The_scope_allows_only_its_operations()
    {
        Assert.Equal(FilePermissions.List | FilePermissions.Download, ShareRules.PermissionMask(ShareScope.Read, allowOverwrite: true));
        Assert.Equal(FilePermissions.Upload, ShareRules.PermissionMask(ShareScope.Write, allowOverwrite: false));
        Assert.Equal(FilePermissions.Upload | FilePermissions.Overwrite, ShareRules.PermissionMask(ShareScope.Write, allowOverwrite: true));
        Assert.Equal(FilePermissions.List | FilePermissions.Download | FilePermissions.Upload, ShareRules.PermissionMask(ShareScope.ReadWrite, false));
        foreach (var scope in Enum.GetValues<ShareScope>())
        {
            var mask = ShareRules.PermissionMask(scope, true);
            Assert.Equal(FilePermissions.None, mask & (FilePermissions.Delete | FilePermissions.Rename | FilePermissions.CreateDirectories
                | FilePermissions.CreateSymlinks | FilePermissions.ChangeMode | FilePermissions.ChangeTimes));
        }
    }

    [Fact]
    public void Restrict_is_the_intersection_with_the_mask_and_keeps_the_filters()
    {
        var filters = new Dictionary<string, PathFilter> { ["/in"] = new() { DeniedPatterns = ["*.exe"] } };
        var owner = new EffectivePermissions(new Dictionary<string, FilePermissions>
        {
            ["/"] = FilePermissions.All,
            ["/in"] = FilePermissions.Upload | FilePermissions.List,
            ["/ro"] = FilePermissions.List | FilePermissions.Download,
        }, filters);

        var limited = owner.Restrict(FilePermissions.Upload | FilePermissions.Overwrite);

        Assert.Equal(FilePermissions.Upload | FilePermissions.Overwrite, limited.Permissions["/"]);
        Assert.Equal(FilePermissions.Upload, limited.Permissions["/in"]);
        Assert.Equal(FilePermissions.None, limited.Permissions["/ro"]);
        Assert.Same(filters, limited.Filters);
        Assert.False(EffectivePermissions.Unrestricted.Restrict(FilePermissions.Download).IsUnrestricted);
    }
}

/// <summary>The in-memory share store (the LiteDB provider): a copy per call and the limit of the uses.</summary>
public sealed class InMemoryShareStoreTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task TryUse_counts_until_the_limit()
    {
        var store = new InMemoryShareStore();
        var share = new Share { Id = ShareId.New(), UserId = 1, Username = "a", Name = "n", Paths = ["/x"], MaxUses = 2 };
        await store.AddAsync(share, Ct);
        share.Name = "changed"; // the store has a copy

        Assert.True(await store.TryUseAsync(share.Id, DateTime.UtcNow, Ct));
        Assert.True(await store.TryUseAsync(share.Id, DateTime.UtcNow, Ct));
        Assert.False(await store.TryUseAsync(share.Id, DateTime.UtcNow, Ct));
        var stored = await store.GetAsync(share.Id, Ct);
        Assert.Equal(2, stored!.UsedCount);
        Assert.Equal("n", stored.Name);
        Assert.False(await store.TryUseAsync(ShareId.New(), DateTime.UtcNow, Ct));
        Assert.True(await store.RemoveAsync(share.Id, Ct));
        Assert.Empty(await store.ListAsync(1, Ct));
    }
}

/// <summary>The rate limit of the share links per client address.</summary>
public sealed class ShareRateLimiterTests
{
    [Fact]
    public void A_client_gets_the_permits_of_a_minute_and_others_their_own()
    {
        using var limiter = new ShareRateLimiter(Options.Create(new WebClientOptions { ShareRequestsPerMinute = 3 }));

        Assert.True(limiter.TryAcquire("192.0.2.1"));
        Assert.True(limiter.TryAcquire("192.0.2.1"));
        Assert.True(limiter.TryAcquire("192.0.2.1"));
        Assert.False(limiter.TryAcquire("192.0.2.1"));
        Assert.True(limiter.TryAcquire("192.0.2.2"));
    }
}
