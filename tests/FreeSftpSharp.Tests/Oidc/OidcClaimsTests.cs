using System.Security.Claims;
using FxSshSftpServer.Security.Oidc;
using SshServer.Interfaces.Admins;

namespace FreeSftpSharp.Tests.Oidc;

/// <summary>The claim mapping of the OpenID Connect sign-in (#73): user name, roles, groups.</summary>
public sealed class OidcClaimsTests
{
    private static ClaimsPrincipal Principal(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(c => new Claim(c.Type, c.Value, c.Value.StartsWith('{') || c.Value.StartsWith('[') ? "JSON" : ClaimValueTypes.String)), "oidc"));

    [Fact]
    public void The_username_is_the_first_non_empty_value_of_the_claim_trimmed()
    {
        var principal = Principal(("sub", "123"), ("preferred_username", " "), ("preferred_username", " alice "));

        Assert.Equal("alice", OidcClaims.Username(principal, "preferred_username"));
        Assert.Equal("123", OidcClaims.Username(principal, "sub"));
        Assert.Null(OidcClaims.Username(principal, "email"));
    }

    [Fact]
    public void Roles_are_read_from_repeated_claims_a_JSON_array_or_a_path()
    {
        var repeated = Principal(("roles", "a"), ("roles", "b"));
        var array = Principal(("roles", "[\"a\",\"b\"]"));
        var keycloak = Principal(("realm_access", "{\"roles\":[\"offline_access\",\"sftp-admin\"]}"));

        Assert.Equal(["a", "b"], OidcClaims.Values(repeated, "roles"));
        Assert.Equal(["a", "b"], OidcClaims.Values(array, "roles"));
        Assert.Equal(["offline_access", "sftp-admin"], OidcClaims.Values(keycloak, "realm_access.roles"));
        Assert.Empty(OidcClaims.Values(keycloak, "realm_access.missing"));
        Assert.Empty(OidcClaims.Values(keycloak, "resource_access.x.roles"));
        Assert.Empty(OidcClaims.Values(Principal(("realm_access", "not json")), "realm_access.roles"));
    }

    [Fact]
    public void Without_a_required_role_every_account_passes()
    {
        var options = new AdminOidcOptions { RequiredRoleValue = null };

        Assert.True(OidcClaims.HasRequiredRole(Principal(("sub", "1")), options));
    }

    [Fact]
    public void The_required_role_must_be_in_the_role_claim_with_the_same_case()
    {
        var options = new AdminOidcOptions { RoleClaim = "roles", RequiredRoleValue = "sftp-admin" };

        Assert.True(OidcClaims.HasRequiredRole(Principal(("roles", "other"), ("roles", "sftp-admin")), options));
        Assert.False(OidcClaims.HasRequiredRole(Principal(("roles", "SFTP-ADMIN")), options));
        Assert.False(OidcClaims.HasRequiredRole(Principal(("groups", "sftp-admin")), options));
        Assert.False(OidcClaims.HasRequiredRole(Principal(), options));
    }

    [Fact]
    public void Groups_keep_their_names_without_a_map_and_lose_the_Keycloak_path_slash()
    {
        var options = new ClientOidcOptions { GroupsClaim = "groups" };

        Assert.Equal(["staff", "partners"], OidcClaims.Groups(Principal(("groups", "/staff"), ("groups", "partners"), ("groups", "STAFF")), options));
        Assert.Empty(OidcClaims.Groups(Principal(), options)!);
    }

    [Fact]
    public void A_group_map_translates_and_drops_the_unmapped_groups()
    {
        var options = new ClientOidcOptions
        {
            GroupsClaim = "groups",
            GroupMap = new() { ["11111111-aaaa"] = "staff" },
        };

        Assert.Equal(["staff"], OidcClaims.Groups(Principal(("groups", "11111111-aaaa"), ("groups", "22222222-bbbb")), options));
    }

    [Fact]
    public void Without_a_groups_claim_the_groups_are_not_mapped()
    {
        Assert.Null(OidcClaims.Groups(Principal(("groups", "staff")), new ClientOidcOptions { GroupsClaim = "" }));
    }
}

public sealed class OidcSignInOptionsTests
{
    [Fact]
    public void A_section_without_an_authority_is_off_and_valid()
    {
        var options = new ClientOidcOptions();

        Assert.False(options.IsEnabled);
        Assert.Empty(options.Validate(ClientOidcOptions.SectionName));
    }

    [Fact]
    public void An_enabled_section_needs_a_client_id_and_https()
    {
        var errors = new ClientOidcOptions { Authority = "http://idp.example.org" }.Validate(ClientOidcOptions.SectionName);

        Assert.Contains(errors, e => e.Contains("ClientId", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("https", StringComparison.Ordinal));
        Assert.Empty(new ClientOidcOptions { Authority = "http://localhost:8080/realms/x", ClientId = "c", RequireHttpsMetadata = false }
            .Validate(ClientOidcOptions.SectionName));
    }

    [Fact]
    public void Openid_is_always_requested_and_profile_is_the_default()
    {
        Assert.Equal(["openid", "profile"], new ClientOidcOptions().EffectiveScopes());
        Assert.Equal(["openid", "email", "groups"], new ClientOidcOptions { Scopes = ["email", "openid", " groups "] }.EffectiveScopes());
    }

    [Fact]
    public void Admin_auto_provisioning_needs_role_permissions_with_known_names()
    {
        var missing = new AdminOidcOptions { Authority = "https://idp", ClientId = "c", AutoProvision = true }.Validate(AdminOidcOptions.SectionName);
        Assert.Contains(missing, e => e.Contains("RolePermissions", StringComparison.Ordinal));

        var unknown = new AdminOidcOptions
        {
            Authority = "https://idp", ClientId = "c", AutoProvision = true,
            RolePermissions = new() { ["helpdesk"] = "ViewConnections, Fly" },
        };
        Assert.Contains(unknown.Validate(AdminOidcOptions.SectionName), e => e.Contains("'Fly'", StringComparison.Ordinal));

        var valid = new AdminOidcOptions
        {
            Authority = "https://idp", ClientId = "c", AutoProvision = true,
            RolePermissions = new() { ["helpdesk"] = "viewconnections, ViewAudit" },
        };
        Assert.Empty(valid.Validate(AdminOidcOptions.SectionName));
        Assert.Equal(AdminPermissions.ViewConnections | AdminPermissions.ViewAudit, valid.ParseRolePermissions()["helpdesk"]);
    }
}
