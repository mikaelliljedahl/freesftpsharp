using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.SqlServer.Migrations;

/// <inheritdoc />
public partial class _20261114151855_AddAdminAuthenticationProvider : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "AuthenticationProvider",
            table: "Admins",
            type: "nvarchar(64)",
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
