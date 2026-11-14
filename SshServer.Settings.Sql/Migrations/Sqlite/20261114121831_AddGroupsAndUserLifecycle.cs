using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <inheritdoc />
public partial class _20261114121831_AddGroupsAndUserLifecycle : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "SecondaryGroupIds",
            table: "Users",
            type: "TEXT",
            nullable: false,
            defaultValue: "[]");

        migrationBuilder.AddColumn<string>(
            name: "Description",
            table: "Users",
            type: "TEXT",
            maxLength: 1000,
            nullable: true);

        migrationBuilder.AddColumn<DateTime>(
            name: "ExpiresAt",
            table: "Users",
            type: "TEXT",
            nullable: true);

        migrationBuilder.AddColumn<DateTime>(
            name: "LastLoginAt",
            table: "Users",
            type: "TEXT",
            nullable: true);

        // The last login is nullable now; "never" was the default DateTime.
        migrationBuilder.Sql(
            "UPDATE \"Users\" SET \"LastLoginAt\" = \"LastSuccessfulLogin\" WHERE \"LastSuccessfulLogin\" NOT LIKE '0001-01-01%';");

        migrationBuilder.DropColumn(
            name: "LastSuccessfulLogin",
            table: "Users");

        migrationBuilder.AddColumn<int>(
            name: "MaxSessions",
            table: "Users",
            type: "INTEGER",
            nullable: false,
            defaultValue: 0);

        migrationBuilder.AddColumn<DateTime>(
            name: "PasswordChangedAt",
            table: "Users",
            type: "TEXT",
            nullable: true);

        migrationBuilder.AddColumn<int>(
            name: "PrimaryGroupId",
            table: "Users",
            type: "INTEGER",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "Status",
            table: "Users",
            type: "TEXT",
            maxLength: 16,
            nullable: false,
            defaultValue: "Enabled");

        migrationBuilder.AddColumn<int>(
            name: "PasswordMaxAgeDays",
            table: "ServerSettings",
            type: "INTEGER",
            nullable: false,
            defaultValue: 0);

        migrationBuilder.CreateTable(
            name: "Groups",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false, collation: "NOCASE"),
                Description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                Permissions = table.Column<string>(type: "TEXT", nullable: true),
                PathFilters = table.Column<string>(type: "TEXT", nullable: true),
                Storage = table.Column<string>(type: "TEXT", nullable: true),
                AllowedAuthMethods = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                AllowedIps = table.Column<string>(type: "TEXT", nullable: true),
                RoleId = table.Column<int>(type: "INTEGER", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Groups", x => x.Id);
                table.ForeignKey(
                    name: "FK_Groups_Roles_RoleId",
                    column: x => x.RoleId,
                    principalTable: "Roles",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Restrict);
            });

        migrationBuilder.CreateTable(
            name: "GroupVirtualFolders",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                VirtualFolderId = table.Column<int>(type: "INTEGER", nullable: false),
                MountPath = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                GroupId = table.Column<int>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_GroupVirtualFolders", x => x.Id);
                table.ForeignKey(
                    name: "FK_GroupVirtualFolders_Groups_GroupId",
                    column: x => x.GroupId,
                    principalTable: "Groups",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "FK_GroupVirtualFolders_VirtualFolders_VirtualFolderId",
                    column: x => x.VirtualFolderId,
                    principalTable: "VirtualFolders",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_Users_PrimaryGroupId",
            table: "Users",
            column: "PrimaryGroupId");

        migrationBuilder.CreateIndex(
            name: "IX_Groups_Name",
            table: "Groups",
            column: "Name",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_Groups_RoleId",
            table: "Groups",
            column: "RoleId");

        migrationBuilder.CreateIndex(
            name: "IX_GroupVirtualFolders_GroupId_MountPath",
            table: "GroupVirtualFolders",
            columns: new[] { "GroupId", "MountPath" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_GroupVirtualFolders_VirtualFolderId",
            table: "GroupVirtualFolders",
            column: "VirtualFolderId");

        migrationBuilder.AddForeignKey(
            name: "FK_Users_Groups_PrimaryGroupId",
            table: "Users",
            column: "PrimaryGroupId",
            principalTable: "Groups",
            principalColumn: "Id",
            onDelete: ReferentialAction.Restrict);

        // Only "/" = All is the same as no permissions of the user: then the user can take the permissions of a group.
        migrationBuilder.Sql("UPDATE \"Users\" SET \"Permissions\" = NULL WHERE \"Permissions\" = '{\"/\":\"All\"}';");

        // The age of the existing passwords counts from the upgrade (ServerSettings.PasswordMaxAgeDays).
        migrationBuilder.Sql(
            "UPDATE \"Users\" SET \"PasswordChangedAt\" = strftime('%Y-%m-%d %H:%M:%f', 'now') " +
            "WHERE \"HashedPassword\" IS NOT NULL AND \"HashedPassword\" <> '';");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropForeignKey(
            name: "FK_Users_Groups_PrimaryGroupId",
            table: "Users");

        migrationBuilder.DropTable(
            name: "GroupVirtualFolders");

        migrationBuilder.DropTable(
            name: "Groups");

        migrationBuilder.DropIndex(
            name: "IX_Users_PrimaryGroupId",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "Description",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "ExpiresAt",
            table: "Users");

        migrationBuilder.AddColumn<DateTime>(
            name: "LastSuccessfulLogin",
            table: "Users",
            type: "TEXT",
            nullable: false,
            defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

        migrationBuilder.Sql(
            "UPDATE \"Users\" SET \"LastSuccessfulLogin\" = \"LastLoginAt\" WHERE \"LastLoginAt\" IS NOT NULL;");

        migrationBuilder.DropColumn(
            name: "LastLoginAt",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "MaxSessions",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "PasswordChangedAt",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "PrimaryGroupId",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "Status",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "PasswordMaxAgeDays",
            table: "ServerSettings");

        migrationBuilder.DropColumn(
            name: "SecondaryGroupIds",
            table: "Users");
    }
}
