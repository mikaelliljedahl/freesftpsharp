using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <summary>
/// Issue #58: the key list, the allowed login methods and the multi-step login of a user. Every existing user gets
/// <c>All</c> methods (as before) and no multi-step login. The old column RsaPublicKey stays: the repository moves its
/// key to the key list at start (a CSP blob cannot be converted in SQL) and clears it.
/// (Edited by hand: the default value "All".)
/// </summary>
public partial class _20261114110144_AddUserPublicKeysAndAuthMethods : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "AllowedAuthMethods",
            table: "Users",
            type: "TEXT",
            maxLength: 128,
            nullable: false,
            defaultValue: "All");

        migrationBuilder.AddColumn<string>(
            name: "PublicKeys",
            table: "Users",
            type: "TEXT",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "RequireAllOf",
            table: "Users",
            type: "TEXT",
            nullable: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(
            name: "AllowedAuthMethods",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "PublicKeys",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "RequireAllOf",
            table: "Users");
    }
}
