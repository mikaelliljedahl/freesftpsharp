using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <inheritdoc />
public partial class _20261114133236_AddUserAuthenticationProvider : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "AuthenticationProvider",
            table: "Users",
            type: "TEXT",
            maxLength: 64,
            nullable: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(
            name: "AuthenticationProvider",
            table: "Users");
    }
}
