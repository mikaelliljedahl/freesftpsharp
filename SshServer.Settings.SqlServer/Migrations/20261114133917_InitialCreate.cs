using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshServer.Settings.SqlServer.Migrations;

/// <inheritdoc />
public partial class _20261114133917_InitialCreate : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "ApiSigningKeys",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false),
                ProtectedKey = table.Column<string>(type: "nvarchar(max)", nullable: false),
                CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ApiSigningKeys", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "AuditEntries",
            columns: table => new
            {
                Id = table.Column<long>(type: "bigint", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                TimestampUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                Category = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                Type = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                Actor = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                Username = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                RemoteIp = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                Protocol = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: true),
                SessionId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                Path = table.Column<string>(type: "nvarchar(max)", nullable: true),
                TargetPath = table.Column<string>(type: "nvarchar(max)", nullable: true),
                Size = table.Column<long>(type: "bigint", nullable: true),
                ElapsedMilliseconds = table.Column<long>(type: "bigint", nullable: true),
                Status = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                Message = table.Column<string>(type: "nvarchar(max)", nullable: true),
                Details = table.Column<string>(type: "nvarchar(max)", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AuditEntries", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "EventRules",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                Name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                Description = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: true),
                Enabled = table.Column<bool>(type: "bit", nullable: false),
                Trigger = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                EventTypes = table.Column<string>(type: "nvarchar(max)", nullable: false),
                CronExpression = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                TimeZone = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                Conditions = table.Column<string>(type: "nvarchar(max)", nullable: false),
                Actions = table.Column<string>(type: "nvarchar(max)", nullable: false),
                LastScheduledRunUtc = table.Column<DateTime>(type: "datetime2", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_EventRules", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "QuotaUsages",
            columns: table => new
            {
                Scope = table.Column<string>(type: "nvarchar(300)", maxLength: 300, nullable: false),
                UsedBytes = table.Column<long>(type: "bigint", nullable: false),
                UsedFiles = table.Column<long>(type: "bigint", nullable: false),
                UploadedBytes = table.Column<long>(type: "bigint", nullable: false),
                DownloadedBytes = table.Column<long>(type: "bigint", nullable: false),
                ScannedUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                UpdatedUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_QuotaUsages", x => x.Scope);
            });

        migrationBuilder.CreateTable(
            name: "Roles",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                Name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                Description = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Roles", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "ServerSettings",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                ServerRsaKey = table.Column<string>(type: "nvarchar(max)", nullable: true),
                ServerEcdsaKey = table.Column<string>(type: "nvarchar(max)", nullable: true),
                ServerBanner = table.Column<string>(type: "nvarchar(max)", nullable: true),
                ListenToPort = table.Column<int>(type: "int", nullable: false),
                BindToAddress = table.Column<string>(type: "nvarchar(max)", nullable: true),
                BlacklistedIps = table.Column<string>(type: "nvarchar(max)", nullable: true),
                OnlyWhitelistedIps = table.Column<bool>(type: "bit", nullable: false),
                WhitelistedIps = table.Column<string>(type: "nvarchar(max)", nullable: true),
                MaxLoginAttemptsBeforeBan = table.Column<int>(type: "int", nullable: false),
                LoginFailureWindowSeconds = table.Column<int>(type: "int", nullable: false),
                BanDurationSeconds = table.Column<int>(type: "int", nullable: false),
                ExemptLoopbackFromBan = table.Column<bool>(type: "bit", nullable: false),
                PasswordMaxAgeDays = table.Column<int>(type: "int", nullable: false),
                IdleTimeout = table.Column<int>(type: "int", nullable: false),
                EnableCommand = table.Column<bool>(type: "bit", nullable: false),
                EnableDirectTcpIp = table.Column<bool>(type: "bit", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ServerSettings", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "VirtualFolders",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                Name = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
                Storage = table.Column<string>(type: "nvarchar(max)", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_VirtualFolders", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "Webhooks",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                Name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                Url = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: false),
                Method = table.Column<string>(type: "nvarchar(8)", maxLength: 8, nullable: false),
                ProtectedSecret = table.Column<string>(type: "nvarchar(max)", nullable: true),
                Headers = table.Column<string>(type: "nvarchar(max)", nullable: false),
                EventTypes = table.Column<string>(type: "nvarchar(max)", nullable: false),
                Users = table.Column<string>(type: "nvarchar(max)", nullable: false),
                PathGlob = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: true),
                Sync = table.Column<bool>(type: "bit", nullable: false),
                FailOpen = table.Column<bool>(type: "bit", nullable: false),
                TimeoutSeconds = table.Column<int>(type: "int", nullable: false),
                Enabled = table.Column<bool>(type: "bit", nullable: false),
                OnlyForEventRules = table.Column<bool>(type: "bit", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Webhooks", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "EventRuleRuns",
            columns: table => new
            {
                Id = table.Column<long>(type: "bigint", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                RuleId = table.Column<int>(type: "int", nullable: false),
                StartedUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                DurationMs = table.Column<long>(type: "bigint", nullable: false),
                Status = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                Trigger = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                Username = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                Message = table.Column<string>(type: "nvarchar(4000)", maxLength: 4000, nullable: false)
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

        migrationBuilder.CreateTable(
            name: "Admins",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                Username = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                PasswordHash = table.Column<string>(type: "nvarchar(max)", nullable: false),
                Status = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                Email = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                Permissions = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                AllowedIps = table.Column<string>(type: "nvarchar(max)", nullable: true),
                ScopeRoleId = table.Column<int>(type: "int", nullable: true),
                LastLoginAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                MustChangePassword = table.Column<bool>(type: "bit", nullable: false)
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

        migrationBuilder.CreateTable(
            name: "Groups",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                Name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                Description = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: true),
                Permissions = table.Column<string>(type: "nvarchar(max)", nullable: true),
                PathFilters = table.Column<string>(type: "nvarchar(max)", nullable: true),
                Storage = table.Column<string>(type: "nvarchar(max)", nullable: true),
                AllowedAuthMethods = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                AllowedIps = table.Column<string>(type: "nvarchar(max)", nullable: true),
                DiskQuota = table.Column<string>(type: "nvarchar(max)", nullable: true),
                TransferQuota = table.Column<string>(type: "nvarchar(max)", nullable: true),
                Bandwidth = table.Column<string>(type: "nvarchar(max)", nullable: true),
                RoleId = table.Column<int>(type: "int", nullable: true)
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
            name: "WebhookDeliveries",
            columns: table => new
            {
                Id = table.Column<long>(type: "bigint", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                DeliveryId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                WebhookId = table.Column<int>(type: "int", nullable: false),
                EventId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                EventType = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                Payload = table.Column<string>(type: "nvarchar(max)", nullable: false),
                Sync = table.Column<bool>(type: "bit", nullable: false),
                Status = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                Attempts = table.Column<int>(type: "int", nullable: false),
                CreatedUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                NextAttemptUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                LastAttemptUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                LastStatusCode = table.Column<int>(type: "int", nullable: true),
                LastError = table.Column<string>(type: "nvarchar(max)", nullable: true),
                ResponseExcerpt = table.Column<string>(type: "nvarchar(max)", nullable: true),
                LeaseOwner = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                LeaseUntilUtc = table.Column<DateTime>(type: "datetime2", nullable: true)
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

        migrationBuilder.CreateTable(
            name: "ApiKeys",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                Name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                Prefix = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                KeyHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                AdminId = table.Column<int>(type: "int", nullable: false),
                Scopes = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                LastUsedAt = table.Column<DateTime>(type: "datetime2", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ApiKeys", x => x.Id);
                table.ForeignKey(
                    name: "FK_ApiKeys_Admins_AdminId",
                    column: x => x.AdminId,
                    principalTable: "Admins",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "GroupVirtualFolders",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                VirtualFolderId = table.Column<int>(type: "int", nullable: false),
                MountPath = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                Quota = table.Column<string>(type: "nvarchar(max)", nullable: true),
                GroupId = table.Column<int>(type: "int", nullable: false)
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

        migrationBuilder.CreateTable(
            name: "Users",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                Username = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                UserRootDirectory = table.Column<string>(type: "nvarchar(max)", nullable: true),
                HashedPassword = table.Column<string>(type: "nvarchar(max)", nullable: true),
                PublicKeys = table.Column<string>(type: "nvarchar(max)", nullable: true),
                AllowedAuthMethods = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                RequireAllOf = table.Column<string>(type: "nvarchar(max)", nullable: true),
                AllowedProtocols = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                AppPasswords = table.Column<string>(type: "nvarchar(max)", nullable: true),
                OnlyWhitelistedIps = table.Column<bool>(type: "bit", nullable: false),
                WhitelistedIps = table.Column<string>(type: "nvarchar(max)", nullable: true),
                LastLoginAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                Description = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: true),
                Status = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                MaxSessions = table.Column<int>(type: "int", nullable: false),
                PasswordChangedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                PrimaryGroupId = table.Column<int>(type: "int", nullable: true),
                SecondaryGroupIds = table.Column<string>(type: "nvarchar(max)", nullable: false),
                Permissions = table.Column<string>(type: "nvarchar(max)", nullable: true),
                PathFilters = table.Column<string>(type: "nvarchar(max)", nullable: true),
                Storage = table.Column<string>(type: "nvarchar(max)", nullable: true),
                DiskQuota = table.Column<string>(type: "nvarchar(max)", nullable: true),
                TransferQuota = table.Column<string>(type: "nvarchar(max)", nullable: true),
                Bandwidth = table.Column<string>(type: "nvarchar(max)", nullable: true),
                RoleId = table.Column<int>(type: "int", nullable: true),
                RsaPublicKey = table.Column<string>(type: "nvarchar(max)", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Users", x => x.Id);
                table.ForeignKey(
                    name: "FK_Users_Groups_PrimaryGroupId",
                    column: x => x.PrimaryGroupId,
                    principalTable: "Groups",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Restrict);
                table.ForeignKey(
                    name: "FK_Users_Roles_RoleId",
                    column: x => x.RoleId,
                    principalTable: "Roles",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Restrict);
            });

        migrationBuilder.CreateTable(
            name: "TwoFactorEnrolments",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                UserId = table.Column<int>(type: "int", nullable: true),
                AdminId = table.Column<int>(type: "int", nullable: true),
                ProtectedSecret = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                Enabled = table.Column<bool>(type: "bit", nullable: false),
                LastUsedStep = table.Column<long>(type: "bigint", nullable: false),
                RecoveryCodeHashes = table.Column<string>(type: "nvarchar(max)", nullable: false),
                CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                EnabledAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                Version = table.Column<int>(type: "int", nullable: false)
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

        migrationBuilder.CreateTable(
            name: "UserVirtualFolders",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                VirtualFolderId = table.Column<int>(type: "int", nullable: false),
                MountPath = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                Quota = table.Column<string>(type: "nvarchar(max)", nullable: true),
                UserId = table.Column<int>(type: "int", nullable: false)
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
            name: "IX_Admins_ScopeRoleId",
            table: "Admins",
            column: "ScopeRoleId");

        migrationBuilder.CreateIndex(
            name: "IX_Admins_Username",
            table: "Admins",
            column: "Username",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_ApiKeys_AdminId_Name",
            table: "ApiKeys",
            columns: new[] { "AdminId", "Name" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_ApiKeys_KeyHash",
            table: "ApiKeys",
            column: "KeyHash",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_AuditEntries_TimestampUtc",
            table: "AuditEntries",
            column: "TimestampUtc");

        migrationBuilder.CreateIndex(
            name: "IX_AuditEntries_Username",
            table: "AuditEntries",
            column: "Username");

        migrationBuilder.CreateIndex(
            name: "IX_EventRuleRuns_RuleId_StartedUtc",
            table: "EventRuleRuns",
            columns: new[] { "RuleId", "StartedUtc" });

        migrationBuilder.CreateIndex(
            name: "IX_EventRules_Name",
            table: "EventRules",
            column: "Name",
            unique: true);

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

        migrationBuilder.CreateIndex(
            name: "IX_Roles_Name",
            table: "Roles",
            column: "Name",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_TwoFactorEnrolments_AdminId",
            table: "TwoFactorEnrolments",
            column: "AdminId",
            unique: true,
            filter: "[AdminId] IS NOT NULL");

        migrationBuilder.CreateIndex(
            name: "IX_TwoFactorEnrolments_UserId",
            table: "TwoFactorEnrolments",
            column: "UserId",
            unique: true,
            filter: "[UserId] IS NOT NULL");

        migrationBuilder.CreateIndex(
            name: "IX_Users_PrimaryGroupId",
            table: "Users",
            column: "PrimaryGroupId");

        migrationBuilder.CreateIndex(
            name: "IX_Users_RoleId",
            table: "Users",
            column: "RoleId");

        migrationBuilder.CreateIndex(
            name: "IX_Users_Username",
            table: "Users",
            column: "Username",
            unique: true);

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
            name: "ApiKeys");

        migrationBuilder.DropTable(
            name: "ApiSigningKeys");

        migrationBuilder.DropTable(
            name: "AuditEntries");

        migrationBuilder.DropTable(
            name: "EventRuleRuns");

        migrationBuilder.DropTable(
            name: "GroupVirtualFolders");

        migrationBuilder.DropTable(
            name: "QuotaUsages");

        migrationBuilder.DropTable(
            name: "ServerSettings");

        migrationBuilder.DropTable(
            name: "TwoFactorEnrolments");

        migrationBuilder.DropTable(
            name: "UserVirtualFolders");

        migrationBuilder.DropTable(
            name: "WebhookDeliveries");

        migrationBuilder.DropTable(
            name: "EventRules");

        migrationBuilder.DropTable(
            name: "Admins");

        migrationBuilder.DropTable(
            name: "Users");

        migrationBuilder.DropTable(
            name: "VirtualFolders");

        migrationBuilder.DropTable(
            name: "Webhooks");

        migrationBuilder.DropTable(
            name: "Groups");

        migrationBuilder.DropTable(
            name: "Roles");
    }
}
