using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.SqlServer.Migrations;

/// <inheritdoc />
public partial class _20261114154851_SingleServerSettingsRow : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // A database that two nodes created at the same time can have more than one row (#149). Every read took the row
        // with the lowest id, so that one stays.
        migrationBuilder.Sql("DELETE FROM \"ServerSettings\" WHERE \"Id\" > (SELECT MIN(\"Id\") FROM \"ServerSettings\");");

        migrationBuilder.AddColumn<int>(
            name: "Singleton",
            table: "ServerSettings",
            type: "int",
            nullable: false,
            defaultValue: 1);

        migrationBuilder.CreateIndex(
            name: "IX_ServerSettings_Singleton",
            table: "ServerSettings",
            column: "Singleton",
            unique: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex(
            name: "IX_ServerSettings_Singleton",
            table: "ServerSettings");

        migrationBuilder.DropColumn(
            name: "Singleton",
            table: "ServerSettings");
    }
}
