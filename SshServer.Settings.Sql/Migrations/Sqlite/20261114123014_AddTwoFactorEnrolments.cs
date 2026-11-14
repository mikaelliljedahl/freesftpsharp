using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <inheritdoc />
public partial class _20261114123014_AddTwoFactorEnrolments : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "TwoFactorEnrolments",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                UserId = table.Column<int>(type: "INTEGER", nullable: true),
                AdminId = table.Column<int>(type: "INTEGER", nullable: true),
                ProtectedSecret = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                LastUsedStep = table.Column<long>(type: "INTEGER", nullable: false),
                RecoveryCodeHashes = table.Column<string>(type: "TEXT", nullable: false),
                CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                EnabledAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                Version = table.Column<int>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_TwoFactorEnrolments", x => x.Id);
                table.CheckConstraint("CK_TwoFactorEnrolments_Owner", "(UserId IS NULL AND AdminId IS NOT NULL) OR (UserId IS NOT NULL AND AdminId IS NULL)");
                table.ForeignKey(
                    name: "FK_TwoFactorEnrolments_Admins_AdminId",
                    column: x => x.AdminId,
                    principalTable: "Admins",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "FK_TwoFactorEnrolments_Users_UserId",
                    column: x => x.UserId,
                    principalTable: "Users",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_TwoFactorEnrolments_AdminId",
            table: "TwoFactorEnrolments",
            column: "AdminId",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_TwoFactorEnrolments_UserId",
            table: "TwoFactorEnrolments",
            column: "UserId",
            unique: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "TwoFactorEnrolments");
    }
}
