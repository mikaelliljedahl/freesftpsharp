using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <summary>
/// Issue #43: the global whitelist mode and the auto-ban settings. Existing rows get the same defaults as a new
/// <c>ServerSettings</c> (window 600 s, ban 1800 s, loopback exempt, whitelist mode off); their
/// MaxLoginAttemptsBeforeBan is kept. ServerRootDirectory was never used and is removed.
/// (Edited by hand: EF suggested renaming ServerRootDirectory to WhitelistedIps, which would read old paths as JSON.)
/// </summary>
public partial class _20261113221412_AddIpFilterAndBanSettings : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(
            name: "ServerRootDirectory",
            table: "ServerSettings");

        migrationBuilder.AddColumn<string>(
            name: "WhitelistedIps",
            table: "ServerSettings",
            type: "TEXT",
            nullable: true);

        migrationBuilder.AddColumn<bool>(
            name: "OnlyWhitelistedIps",
            table: "ServerSettings",
            type: "INTEGER",
            nullable: false,
            defaultValue: false);

        migrationBuilder.AddColumn<int>(
            name: "LoginFailureWindowSeconds",
            table: "ServerSettings",
            type: "INTEGER",
            nullable: false,
            defaultValue: 600);

        migrationBuilder.AddColumn<int>(
            name: "BanDurationSeconds",
            table: "ServerSettings",
            type: "INTEGER",
            nullable: false,
            defaultValue: 1800);

        migrationBuilder.AddColumn<bool>(
            name: "ExemptLoopbackFromBan",
            table: "ServerSettings",
            type: "INTEGER",
            nullable: false,
            defaultValue: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(
            name: "BanDurationSeconds",
            table: "ServerSettings");

        migrationBuilder.DropColumn(
            name: "ExemptLoopbackFromBan",
            table: "ServerSettings");

        migrationBuilder.DropColumn(
            name: "LoginFailureWindowSeconds",
            table: "ServerSettings");

        migrationBuilder.DropColumn(
            name: "OnlyWhitelistedIps",
            table: "ServerSettings");

        migrationBuilder.DropColumn(
            name: "WhitelistedIps",
            table: "ServerSettings");

        migrationBuilder.AddColumn<string>(
            name: "ServerRootDirectory",
            table: "ServerSettings",
            type: "TEXT",
            nullable: true);
    }
}
