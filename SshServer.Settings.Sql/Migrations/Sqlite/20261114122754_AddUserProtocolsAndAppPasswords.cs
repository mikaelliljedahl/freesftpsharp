using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <inheritdoc />
public partial class _20261114122754_AddUserProtocolsAndAppPasswords : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // Existing users keep every protocol (SFTP), as before the column existed.
        migrationBuilder.AddColumn<string>(
            name: "AllowedProtocols",
            table: "Users",
            type: "TEXT",
            maxLength: 128,
            nullable: false,
            defaultValue: "All");

        migrationBuilder.AddColumn<string>(
            name: "AppPasswords",
            table: "Users",
            type: "TEXT",
            nullable: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(
            name: "AllowedProtocols",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "AppPasswords",
            table: "Users");
    }
}
