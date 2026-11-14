using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <inheritdoc />
public partial class _20261114105731_AddWebhooks : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "Webhooks",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false, collation: "NOCASE"),
                Url = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                Method = table.Column<string>(type: "TEXT", maxLength: 8, nullable: false),
                ProtectedSecret = table.Column<string>(type: "TEXT", nullable: true),
                Headers = table.Column<string>(type: "TEXT", nullable: false),
                EventTypes = table.Column<string>(type: "TEXT", nullable: false),
                Users = table.Column<string>(type: "TEXT", nullable: false),
                PathGlob = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                Sync = table.Column<bool>(type: "INTEGER", nullable: false),
                FailOpen = table.Column<bool>(type: "INTEGER", nullable: false),
                TimeoutSeconds = table.Column<int>(type: "INTEGER", nullable: false),
                Enabled = table.Column<bool>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Webhooks", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "WebhookDeliveries",
            columns: table => new
            {
                Id = table.Column<long>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                DeliveryId = table.Column<Guid>(type: "TEXT", nullable: false),
                WebhookId = table.Column<int>(type: "INTEGER", nullable: false),
                EventId = table.Column<Guid>(type: "TEXT", nullable: false),
                EventType = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                Payload = table.Column<string>(type: "TEXT", nullable: false),
                Sync = table.Column<bool>(type: "INTEGER", nullable: false),
                Status = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                Attempts = table.Column<int>(type: "INTEGER", nullable: false),
                CreatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                NextAttemptUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                LastAttemptUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                LastStatusCode = table.Column<int>(type: "INTEGER", nullable: true),
                LastError = table.Column<string>(type: "TEXT", nullable: true),
                ResponseExcerpt = table.Column<string>(type: "TEXT", nullable: true),
                LeaseOwner = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                LeaseUntilUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_WebhookDeliveries", x => x.Id);
                table.ForeignKey(
                    name: "FK_WebhookDeliveries_Webhooks_WebhookId",
                    column: x => x.WebhookId,
                    principalTable: "Webhooks",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_WebhookDeliveries_DeliveryId",
            table: "WebhookDeliveries",
            column: "DeliveryId",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_WebhookDeliveries_Status_NextAttemptUtc",
            table: "WebhookDeliveries",
            columns: new[] { "Status", "NextAttemptUtc" });

        migrationBuilder.CreateIndex(
            name: "IX_WebhookDeliveries_WebhookId_CreatedUtc",
            table: "WebhookDeliveries",
            columns: new[] { "WebhookId", "CreatedUtc" });

        migrationBuilder.CreateIndex(
            name: "IX_Webhooks_Name",
            table: "Webhooks",
            column: "Name",
            unique: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "WebhookDeliveries");

        migrationBuilder.DropTable(
            name: "Webhooks");
    }
}
