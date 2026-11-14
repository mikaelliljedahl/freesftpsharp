using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <inheritdoc />
public partial class _20261114080100_AddAuditLog : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "AuditEntries",
            columns: table => new
            {
                Id = table.Column<long>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                TimestampUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                Category = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                Type = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                Actor = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                Username = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                RemoteIp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                Protocol = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                SessionId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                Path = table.Column<string>(type: "TEXT", nullable: true),
                TargetPath = table.Column<string>(type: "TEXT", nullable: true),
                Size = table.Column<long>(type: "INTEGER", nullable: true),
                ElapsedMilliseconds = table.Column<long>(type: "INTEGER", nullable: true),
                Status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                Message = table.Column<string>(type: "TEXT", nullable: true),
                Details = table.Column<string>(type: "TEXT", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AuditEntries", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_AuditEntries_TimestampUtc",
            table: "AuditEntries",
            column: "TimestampUtc");

        migrationBuilder.CreateIndex(
            name: "IX_AuditEntries_Username",
            table: "AuditEntries",
            column: "Username");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "AuditEntries");
    }
}
