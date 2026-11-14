using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <inheritdoc />
public partial class _20261114141126_AddClusterState : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "BannedIps",
            columns: table => new
            {
                Address = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                BannedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                ExpiresUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                FailedAttempts = table.Column<int>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_BannedIps", x => x.Address);
            });

        migrationBuilder.CreateTable(
            name: "Connections",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "TEXT", nullable: false),
                NodeId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                Protocol = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                RemoteEndPoint = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                ClientVersion = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                ConnectedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                LastActivityUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                Username = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                AuthenticatedUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                AuthMethod = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                Transfers = table.Column<string>(type: "TEXT", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Connections", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "DataProtectionKeys",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                FriendlyName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                Xml = table.Column<string>(type: "TEXT", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_DataProtectionKeys", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "DisconnectRequests",
            columns: table => new
            {
                Id = table.Column<long>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                NodeId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                ConnectionId = table.Column<Guid>(type: "TEXT", nullable: false),
                Reason = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                CreatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_DisconnectRequests", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "Nodes",
            columns: table => new
            {
                NodeId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                Hostname = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                Version = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                StartedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                LastSeenUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Nodes", x => x.NodeId);
            });

        migrationBuilder.CreateTable(
            name: "SettingsVersions",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false),
                Version = table.Column<long>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_SettingsVersions", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_BannedIps_ExpiresUtc",
            table: "BannedIps",
            column: "ExpiresUtc");

        migrationBuilder.CreateIndex(
            name: "IX_Connections_NodeId",
            table: "Connections",
            column: "NodeId");

        migrationBuilder.CreateIndex(
            name: "IX_DisconnectRequests_NodeId",
            table: "DisconnectRequests",
            column: "NodeId");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "BannedIps");

        migrationBuilder.DropTable(
            name: "Connections");

        migrationBuilder.DropTable(
            name: "DataProtectionKeys");

        migrationBuilder.DropTable(
            name: "DisconnectRequests");

        migrationBuilder.DropTable(
            name: "Nodes");

        migrationBuilder.DropTable(
            name: "SettingsVersions");
    }
}
