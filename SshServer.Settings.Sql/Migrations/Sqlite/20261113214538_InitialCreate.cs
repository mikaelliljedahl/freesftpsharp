using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ServerSettings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ServerRsaKey = table.Column<string>(type: "TEXT", nullable: true),
                    ServerBanner = table.Column<string>(type: "TEXT", nullable: true),
                    ListenToPort = table.Column<int>(type: "INTEGER", nullable: false),
                    ServerRootDirectory = table.Column<string>(type: "TEXT", nullable: true),
                    BindToAddress = table.Column<string>(type: "TEXT", nullable: true),
                    BlacklistedIps = table.Column<string>(type: "TEXT", nullable: true),
                    MaxLoginAttemptsBeforeBan = table.Column<int>(type: "INTEGER", nullable: false),
                    IdleTimeout = table.Column<int>(type: "INTEGER", nullable: false),
                    EnableCommand = table.Column<bool>(type: "INTEGER", nullable: false),
                    EnableDirectTcpIp = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ServerSettings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Username = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false, collation: "NOCASE"),
                    UserRootDirectory = table.Column<string>(type: "TEXT", nullable: true),
                    HashedPassword = table.Column<string>(type: "TEXT", nullable: true),
                    RsaPublicKey = table.Column<string>(type: "TEXT", nullable: true),
                    OnlyWhitelistedIps = table.Column<bool>(type: "INTEGER", nullable: false),
                    WhitelistedIps = table.Column<string>(type: "TEXT", nullable: true),
                    LastSuccessfulLogin = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Users_Username",
                table: "Users",
                column: "Username",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ServerSettings");

            migrationBuilder.DropTable(
                name: "Users");
        }
    }
}
