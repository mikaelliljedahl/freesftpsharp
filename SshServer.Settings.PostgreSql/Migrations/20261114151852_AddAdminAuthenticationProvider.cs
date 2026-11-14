using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.PostgreSql.Migrations;

/// <inheritdoc />
public partial class _20261114151852_AddAdminAuthenticationProvider : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "AuthenticationProvider",
            table: "Admins",
            type: "character varying(64)",
            maxLength: 64,
            nullable: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(
            name: "AuthenticationProvider",
            table: "Admins");
    }
}
