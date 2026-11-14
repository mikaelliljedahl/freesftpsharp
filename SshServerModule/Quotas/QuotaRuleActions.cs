#nullable enable
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Quotas;

namespace SshServerModule.Quotas
{
    /// <summary>
    /// The event rule action "QuotaScan" (#62, #68): queues a scan of every scope with a disk quota of the user of the run,
    /// for example from a nightly scheduled rule or after an upload. The scan runs on the background task of
    /// <see cref="QuotaScanService"/>, so a large storage does not hold the rule worker.
    /// </summary>
    public sealed class QuotaScanRuleAction : IEventRuleAction
    {
        private readonly QuotaScanQueue _scans;

        public QuotaScanRuleAction(QuotaScanQueue scans)
        {
            _scans = scans;
        }

        public string Type => "QuotaScan";

        public string DisplayName => "Rescan quota";

        public string Description => "Recomputes the disk usage of the user from its storage (the scopes with a disk quota).";

        public bool NeedsUser => true;

        public IReadOnlyList<EventActionField> Fields { get; } = [];

        public IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options) => [];

        public Task<EventActionResult> ExecuteAsync(EventActionContext context, CancellationToken ct)
        {
            if (context.User is not { } user)
                return Task.FromResult(EventActionResult.Failed("The run has no user."));
            _scans.RequestUser(user.Username);
            return Task.FromResult(EventActionResult.Ok($"Queued a quota scan of {user.Username}."));
        }
    }

    /// <summary>The event rule action "QuotaResetTransfer" (#62, #68): sets the uploaded and downloaded bytes of the user to 0, for example monthly.</summary>
    public sealed class QuotaResetTransferRuleAction : IEventRuleAction
    {
        private readonly QuotaUsageTracker _tracker;

        public QuotaResetTransferRuleAction(QuotaUsageTracker tracker)
        {
            _tracker = tracker;
        }

        public string Type => "QuotaResetTransfer";

        public string DisplayName => "Reset transfer quota";

        public string Description => "Sets the uploaded and downloaded bytes of the user to 0, so its transfer quota starts again.";

        public bool NeedsUser => true;

        public IReadOnlyList<EventActionField> Fields { get; } = [];

        public IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options) => [];

        public async Task<EventActionResult> ExecuteAsync(EventActionContext context, CancellationToken ct)
        {
            if (context.User is not { } user)
                return EventActionResult.Failed("The run has no user.");
            await _tracker.ResetTransferAsync(QuotaScope.ForUser(user.Username), ct);
            return EventActionResult.Ok($"Reset the transfer counters of {user.Username}.");
        }
    }
}
