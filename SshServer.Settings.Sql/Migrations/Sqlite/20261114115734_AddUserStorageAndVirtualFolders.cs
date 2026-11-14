using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <inheritdoc />
public partial class _20261114115734_AddUserStorageAndVirtualFolders : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "Storage",
            table: "Users",
            type: "TEXT",
            nullable: true);

        migrationBuilder.CreateTable(
            name: "VirtualFolders",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                Name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false, collation: "NOCASE"),
                Description = table.Column<string>(type: "TEXT", nullable: true),
                Storage = table.Column<string>(type: "TEXT", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_VirtualFolders", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "UserVirtualFolders",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                VirtualFolderId = table.Column<int>(type: "INTEGER", nullable: false),
                MountPath = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                UserId = table.Column<int>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_UserVirtualFolders", x => x.Id);
                table.ForeignKey(
                    name: "FK_UserVirtualFolders_Users_UserId",
                    column: x => x.UserId,
                    principalTable: "Users",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "FK_UserVirtualFolders_VirtualFolders_VirtualFolderId",
                    column: x => x.VirtualFolderId,
                    principalTable: "VirtualFolders",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_UserVirtualFolders_UserId_MountPath",
            table: "UserVirtualFolders",
            columns: new[] { "UserId", "MountPath" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_UserVirtualFolders_VirtualFolderId",
            table: "UserVirtualFolders",
            column: "VirtualFolderId");

        migrationBuilder.CreateIndex(
            name: "IX_VirtualFolders_Name",
            table: "VirtualFolders",
            column: "Name",
            unique: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "UserVirtualFolders");

        migrationBuilder.DropTable(
            name: "VirtualFolders");

        migrationBuilder.DropColumn(
            name: "Storage",
            table: "Users");
    }
}
