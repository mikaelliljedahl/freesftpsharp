using System;
using System.Collections.Generic;
using System.Linq;
using SshServer.Interfaces.Webhooks;
using SshServer.Webhooks;

namespace FxSshSftpServer.Models
{
    /// <summary>The add/edit form of a webhook. The rules are checked by <see cref="WebhookAdministrationService"/>.</summary>
    public sealed class WebhookForm
    {
        public int? Id { get; set; }

        public bool IsNew => Id is null;

        public string Name { get; set; } = "";

        public string Url { get; set; } = "";

        public string Method { get; set; } = Webhook.MethodPost;

        /// <summary>A new secret. Empty: keep the stored one. A new webhook gets a random one, shown once.</summary>
        public string NewSecret { get; set; } = "";

        public bool HasSecret { get; set; }

        public bool RemoveSecret { get; set; }

        /// <summary>The static headers, one "Name: value" per line.</summary>
        public string Headers { get; set; } = "";

        public HashSet<string> EventTypes { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>The user filter, one name per line or separated by commas.</summary>
        public string Users { get; set; } = "";

        public string PathGlob { get; set; } = "";

        public bool Sync { get; set; }

        public bool FailOpen { get; set; }

        public int TimeoutSeconds { get; set; } = Webhook.DefaultTimeoutSeconds;

        public bool Enabled { get; set; } = true;

        public bool OnlyForEventRules { get; set; }

        public static WebhookForm New() => new() { NewSecret = WebhookSecretProtector.GenerateSecret() };

        public static WebhookForm From(Webhook webhook)
        {
            var form = new WebhookForm
            {
                Id = webhook.Id,
                Name = webhook.Name,
                Url = webhook.Url,
                Method = webhook.Method,
                HasSecret = !string.IsNullOrEmpty(webhook.ProtectedSecret),
                Headers = string.Join(Environment.NewLine, webhook.Headers.Select(h => $"{h.Key}: {h.Value}")),
                Users = string.Join(Environment.NewLine, webhook.Users),
                PathGlob = webhook.PathGlob ?? "",
                Sync = webhook.Sync,
                FailOpen = webhook.FailOpen,
                TimeoutSeconds = webhook.TimeoutSeconds,
                Enabled = webhook.Enabled,
                OnlyForEventRules = webhook.OnlyForEventRules,
            };
            form.EventTypes.UnionWith(webhook.EventTypes);
            return form;
        }

        /// <summary>The input of the service, or the errors of the header lines.</summary>
        public (WebhookInput Input, IReadOnlyList<string> Errors) ToInput()
        {
            var errors = new List<string>();
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in Lines(Headers))
            {
                var colon = line.IndexOf(':');
                if (colon <= 0)
                {
                    errors.Add($"The header line '{line}' must be 'Name: value'.");
                    continue;
                }
                headers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
            }

            var input = new WebhookInput
            {
                Id = Id,
                Name = Name ?? "",
                Url = Url ?? "",
                Method = Method,
                NewSecret = string.IsNullOrWhiteSpace(NewSecret) ? null : NewSecret.Trim(),
                RemoveSecret = RemoveSecret,
                Headers = headers,
                EventTypes = EventTypes.ToList(),
                Users = Lines(Users).SelectMany(l => l.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToList(),
                PathGlob = PathGlob,
                Sync = Sync,
                FailOpen = Sync && FailOpen,
                TimeoutSeconds = TimeoutSeconds,
                Enabled = Enabled,
                OnlyForEventRules = OnlyForEventRules,
            };
            return (input, errors);
        }

        private static IEnumerable<string> Lines(string text)
            => (text ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
