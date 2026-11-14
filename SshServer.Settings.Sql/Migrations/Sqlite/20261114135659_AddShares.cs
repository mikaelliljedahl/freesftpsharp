using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <inheritdoc />
public partial class _20261114135659_AddShares : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "Shares",
            table: "ServerSettings",
            type: "TEXT",
            nullable: true);

        migrationBuilder.CreateTable(
            name: "Shares",
            columns: table => new
            {
                Id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                UserId = table.Column<int>(type: "INTEGER", nullable: false),
                Username = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                Description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                Paths = table.Column<string>(type: "TEXT", nullable: false),
                Scope = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                AllowOverwrite = table.Column<bool>(type: "INTEGER", nullable: false),
                PasswordHash = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                MaxUses = table.Column<int>(type: "INTEGER", nullable: false),
                UsedCount = table.Column<int>(type: "INTEGER", nullable: false),
                AllowedIps = table.Column<string>(type: "TEXT", nullable: true),
                CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                LastUsedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Shares", x => x.Id);
                table.ForeignKey(
                    name: "FK_Shares_Users_UserId",
                    column: x => x.UserId,
                    principalTable: "Users",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_Shares_UserId",
            table: "Shares",
            column: "UserId");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "Shares");

        migrationBuilder.DropColumn(
            name: "Shares",
            table: "ServerSettings");
    }
}
