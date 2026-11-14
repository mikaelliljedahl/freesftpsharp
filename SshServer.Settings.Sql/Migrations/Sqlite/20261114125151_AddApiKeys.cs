using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <inheritdoc />
public partial class _20261114125151_AddApiKeys : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "ApiKeys",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false, collation: "NOCASE"),
                Prefix = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                KeyHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                AdminId = table.Column<int>(type: "INTEGER", nullable: false),
                Scopes = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                LastUsedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ApiKeys", x => x.Id);
                table.ForeignKey(
                    name: "FK_ApiKeys_Admins_AdminId",
                    column: x => x.AdminId,
                    principalTable: "Admins",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "ApiSigningKeys",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false),
                ProtectedKey = table.Column<string>(type: "TEXT", nullable: false),
                CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ApiSigningKeys", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_ApiKeys_AdminId_Name",
            table: "ApiKeys",
            columns: new[] { "AdminId", "Name" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_ApiKeys_KeyHash",
            table: "ApiKeys",
            column: "KeyHash",
            unique: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "ApiKeys");

        migrationBuilder.DropTable(
            name: "ApiSigningKeys");
    }
}
