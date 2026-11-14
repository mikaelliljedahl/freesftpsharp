using System;
using System.Collections.Generic;
using System.Linq;
using SshServer.Interfaces.Net;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;

namespace FxSshSftpServer.Models
{
    /// <summary>
    /// The quota and bandwidth fields (issue #62) of the user form and of the group form, in MiB and KiB/s. 0 everywhere
    /// is "not set" (for a user: unlimited, or the value of its groups).
    /// </summary>
    public sealed class QuotaForm
    {
        public const decimal BytesPerMiB = 1024 * 1024;

        /// <summary>The disk quota of the own storage in MiB; 0: not set.</summary>
        public decimal SizeMiB { get; set; }

        /// <summary>The maximum number of files of the own storage; 0: not set.</summary>
        public long Files { get; set; }

        /// <summary>The transfer quota in MiB (upload, download, both together); 0: not set.</summary>
        public decimal UploadMiB { get; set; }

        public decimal DownloadMiB { get; set; }

        public decimal TotalMiB { get; set; }

        /// <summary>The bandwidth of a session in KiB/s; 0: not set.</summary>
        public int UploadKiBPerSecond { get; set; }

        public int DownloadKiBPerSecond { get; set; }

        /// <summary>Other bandwidth values for some client networks.</summary>
        public List<BandwidthOverrideRow> Overrides { get; set; } = new();

        public static decimal ToMiB(long bytes) => bytes / BytesPerMiB;

        public static long ToBytes(decimal mib) => (long)Math.Round(mib * BytesPerMiB, MidpointRounding.AwayFromZero);

        public static QuotaForm From(DiskQuota disk, TransferQuota transfer, BandwidthLimit bandwidth) => new()
        {
            SizeMiB = ToMiB(disk?.MaxSizeBytes ?? 0),
            Files = disk?.MaxFiles ?? 0,
            UploadMiB = ToMiB(transfer?.MaxUploadBytes ?? 0),
            DownloadMiB = ToMiB(transfer?.MaxDownloadBytes ?? 0),
            TotalMiB = ToMiB(transfer?.MaxTotalBytes ?? 0),
            UploadKiBPerSecond = bandwidth?.UploadKiBPerSecond ?? 0,
            DownloadKiBPerSecond = bandwidth?.DownloadKiBPerSecond ?? 0,
            Overrides = (bandwidth?.Overrides ?? new List<BandwidthOverride>())
                .Select(o => new BandwidthOverrideRow { Sources = EntryList.Format(o.Sources), UploadKiBPerSecond = o.UploadKiBPerSecond, DownloadKiBPerSecond = o.DownloadKiBPerSecond })
                .ToList(),
        };

        /// <summary>The disk quota; null when it is not set.</summary>
        public DiskQuota Disk => DiskQuota.OrNull(new DiskQuota { MaxSizeBytes = ToBytes(SizeMiB), MaxFiles = Files });

        /// <summary>The transfer quota; null when it is not set.</summary>
        public TransferQuota Transfer => TransferQuota.OrNull(new TransferQuota
        {
            MaxUploadBytes = ToBytes(UploadMiB),
            MaxDownloadBytes = ToBytes(DownloadMiB),
            MaxTotalBytes = ToBytes(TotalMiB),
        });

        /// <summary>The bandwidth; null when nothing is set (an override with 0 is kept: "unlimited for these networks").</summary>
        public BandwidthLimit Bandwidth
        {
            get
            {
                var overrides = Overrides
                    .Select(o => new BandwidthOverride { Sources = EntryList.Parse(o.Sources), UploadKiBPerSecond = o.UploadKiBPerSecond, DownloadKiBPerSecond = o.DownloadKiBPerSecond })
                    .ToList();
                return UploadKiBPerSecond <= 0 && DownloadKiBPerSecond <= 0 && overrides.Count == 0
                    ? null
                    : new BandwidthLimit { UploadKiBPerSecond = UploadKiBPerSecond, DownloadKiBPerSecond = DownloadKiBPerSecond, Overrides = overrides.Count == 0 ? null : overrides };
            }
        }

        /// <summary>The problems of the fields and of the quotas of the mounts; empty when they are valid.</summary>
        public IReadOnlyList<string> Problems(IEnumerable<MountRow> mounts)
        {
            var problems = new List<string>();
            if (SizeMiB < 0 || Files < 0 || (mounts ?? []).Any(m => m.QuotaSizeMiB < 0 || m.QuotaFiles < 0))
                problems.Add("A disk quota cannot be negative (0 is unlimited).");
            if (UploadMiB < 0 || DownloadMiB < 0 || TotalMiB < 0)
                problems.Add("A transfer quota cannot be negative (0 is unlimited).");
            if (UploadKiBPerSecond < 0 || DownloadKiBPerSecond < 0 || Overrides.Any(o => o.UploadKiBPerSecond < 0 || o.DownloadKiBPerSecond < 0))
                problems.Add("A bandwidth cannot be negative (0 is unlimited).");
            foreach (var row in Overrides)
            {
                var sources = EntryList.Parse(row.Sources);
                if (sources.Count == 0)
                    problems.Add("Enter the client networks of each bandwidth override.");
                foreach (var invalid in CidrNotation.FindInvalid(sources))
                    problems.Add($"Not a valid network: {invalid}");
            }
            return problems;
        }
    }

    /// <summary>One virtual folder mounted for a user or a group, in the form, with its disk quota (issue #62).</summary>
    public sealed class MountRow
    {
        public int VirtualFolderId { get; set; }
        public string MountPath { get; set; } = "";

        /// <summary>The disk quota of the folder for this mount in MiB; 0: unlimited.</summary>
        public decimal QuotaSizeMiB { get; set; }

        /// <summary>The maximum number of files in the folder; 0: unlimited.</summary>
        public long QuotaFiles { get; set; }

        public static MountRow From(VirtualFolderMount mount) => new()
        {
            VirtualFolderId = mount.VirtualFolderId,
            MountPath = mount.MountPath,
            QuotaSizeMiB = QuotaForm.ToMiB(mount.Quota?.MaxSizeBytes ?? 0),
            QuotaFiles = mount.Quota?.MaxFiles ?? 0,
        };

        /// <summary>The mount, with the path normalized when it is valid.</summary>
        public VirtualFolderMount ToMount() => new()
        {
            VirtualFolderId = VirtualFolderId,
            MountPath = PermissionTables.NormalizedOrRaw(MountPath),
            Quota = DiskQuota.OrNull(new DiskQuota { MaxSizeBytes = QuotaForm.ToBytes(QuotaSizeMiB), MaxFiles = QuotaFiles }),
        };
    }

    /// <summary>Other bandwidth values for some client networks (issue #62), in the form.</summary>
    public sealed class BandwidthOverrideRow
    {
        /// <summary>The networks in CIDR notation, one per line or separated by commas.</summary>
        public string Sources { get; set; } = "";

        public int UploadKiBPerSecond { get; set; }

        public int DownloadKiBPerSecond { get; set; }
    }
}
