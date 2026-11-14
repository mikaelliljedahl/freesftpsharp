using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.Sql.Migrations.Sqlite;

/// <inheritdoc />
public partial class _20261114121903_AddEventRules : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<bool>(
            name: "OnlyForEventRules",
            table: "Webhooks",
            type: "INTEGER",
            nullable: false,
            defaultValue: false);

        migrationBuilder.CreateTable(
            name: "EventRules",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false, collation: "NOCASE"),
                Description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                Trigger = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                EventTypes = table.Column<string>(type: "TEXT", nullable: false),
                CronExpression = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                TimeZone = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                Conditions = table.Column<string>(type: "TEXT", nullable: false),
                Actions = table.Column<string>(type: "TEXT", nullable: false),
                LastScheduledRunUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_EventRules", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "EventRuleRuns",
            columns: table => new
            {
                Id = table.Column<long>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                RuleId = table.Column<int>(type: "INTEGER", nullable: false),
                StartedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                DurationMs = table.Column<long>(type: "INTEGER", nullable: false),
                Status = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                Trigger = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                Username = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                Message = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_EventRuleRuns", x => x.Id);
                table.ForeignKey(
                    name: "FK_EventRuleRuns_EventRules_RuleId",
                    column: x => x.RuleId,
                    principalTable: "EventRules",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_EventRuleRuns_RuleId_StartedUtc",
            table: "EventRuleRuns",
            columns: new[] { "RuleId", "StartedUtc" });

        migrationBuilder.CreateIndex(
            name: "IX_EventRules_Name",
            table: "EventRules",
            column: "Name",
            unique: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "EventRuleRuns");

        migrationBuilder.DropTable(
            name: "EventRules");

        migrationBuilder.DropColumn(
            name: "OnlyForEventRules",
            table: "Webhooks");
    }
}
