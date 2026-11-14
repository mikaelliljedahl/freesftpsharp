using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <inheritdoc />
public partial class _20261114125655_AddQuotas : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "Quota",
            table: "UserVirtualFolders",
            type: "TEXT",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "Bandwidth",
            table: "Users",
            type: "TEXT",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "DiskQuota",
            table: "Users",
            type: "TEXT",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "TransferQuota",
            table: "Users",
            type: "TEXT",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "Quota",
            table: "GroupVirtualFolders",
            type: "TEXT",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "Bandwidth",
            table: "Groups",
            type: "TEXT",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "DiskQuota",
            table: "Groups",
            type: "TEXT",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "TransferQuota",
            table: "Groups",
            type: "TEXT",
            nullable: true);

        migrationBuilder.CreateTable(
            name: "QuotaUsages",
            columns: table => new
            {
                Scope = table.Column<string>(type: "TEXT", maxLength: 300, nullable: false),
                UsedBytes = table.Column<long>(type: "INTEGER", nullable: false),
                UsedFiles = table.Column<long>(type: "INTEGER", nullable: false),
                UploadedBytes = table.Column<long>(type: "INTEGER", nullable: false),
                DownloadedBytes = table.Column<long>(type: "INTEGER", nullable: false),
                ScannedUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                UpdatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_QuotaUsages", x => x.Scope);
            });
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "QuotaUsages");

        migrationBuilder.DropColumn(
            name: "Quota",
            table: "UserVirtualFolders");

        migrationBuilder.DropColumn(
            name: "Bandwidth",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "DiskQuota",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "TransferQuota",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "Quota",
            table: "GroupVirtualFolders");

        migrationBuilder.DropColumn(
            name: "Bandwidth",
            table: "Groups");

        migrationBuilder.DropColumn(
            name: "DiskQuota",
            table: "Groups");

        migrationBuilder.DropColumn(
            name: "TransferQuota",
            table: "Groups");
    }
}
