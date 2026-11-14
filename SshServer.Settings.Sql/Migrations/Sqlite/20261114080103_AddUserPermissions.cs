using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <summary>
/// Issue #59: the per-path permissions and path filters of a user (JSON text). Every existing user gets
/// <c>{"/":"All"}</c>, the default of a new user, so nobody loses access; the path filters stay empty.
/// (Edited by hand: the UPDATE of the existing rows.)
/// </summary>
public partial class _20261114080103_AddUserPermissions : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "PathFilters",
            table: "Users",
            type: "TEXT",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "Permissions",
            table: "Users",
            type: "TEXT",
            nullable: true);

        migrationBuilder.Sql("UPDATE Users SET Permissions = '{\"/\":\"All\"}' WHERE Permissions IS NULL;");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(
            name: "PathFilters",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "Permissions",
            table: "Users");
    }
}
