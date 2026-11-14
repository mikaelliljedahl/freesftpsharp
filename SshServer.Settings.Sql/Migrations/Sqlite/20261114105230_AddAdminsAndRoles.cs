using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <inheritdoc />
public partial class _20261114105230_AddAdminsAndRoles : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<int>(
            name: "RoleId",
            table: "Users",
            type: "INTEGER",
            nullable: true);

        migrationBuilder.CreateTable(
            name: "Roles",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false, collation: "NOCASE"),
                Description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Roles", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "Admins",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                Username = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false, collation: "NOCASE"),
                PasswordHash = table.Column<string>(type: "TEXT", nullable: false),
                Status = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                Email = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                Permissions = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                AllowedIps = table.Column<string>(type: "TEXT", nullable: true),
                ScopeRoleId = table.Column<int>(type: "INTEGER", nullable: true),
                LastLoginAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                MustChangePassword = table.Column<bool>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Admins", x => x.Id);
                table.ForeignKey(
                    name: "FK_Admins_Roles_ScopeRoleId",
                    column: x => x.ScopeRoleId,
                    principalTable: "Roles",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Restrict);
            });

        migrationBuilder.CreateIndex(
            name: "IX_Users_RoleId",
            table: "Users",
            column: "RoleId");

        migrationBuilder.CreateIndex(
            name: "IX_Admins_ScopeRoleId",
            table: "Admins",
            column: "ScopeRoleId");

        migrationBuilder.CreateIndex(
            name: "IX_Admins_Username",
            table: "Admins",
            column: "Username",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_Roles_Name",
            table: "Roles",
            column: "Name",
            unique: true);

        migrationBuilder.AddForeignKey(
            name: "FK_Users_Roles_RoleId",
            table: "Users",
            column: "RoleId",
            principalTable: "Roles",
            principalColumn: "Id",
            onDelete: ReferentialAction.Restrict);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropForeignKey(
            name: "FK_Users_Roles_RoleId",
            table: "Users");

        migrationBuilder.DropTable(
            name: "Admins");

        migrationBuilder.DropTable(
            name: "Roles");

        migrationBuilder.DropIndex(
            name: "IX_Users_RoleId",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "RoleId",
            table: "Users");
    }
}
