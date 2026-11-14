using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.TwoFactor;
using SshServer.TwoFactor;

namespace SshServer.Administration
{
    /// <summary>Whose second factor a page shows: an SFTP user or an administrator, by name.</summary>
    public sealed record TwoFactorTarget(TwoFactorSubjectKind Kind, string Name)
    {
        public static TwoFactorTarget User(string username) => new(TwoFactorSubjectKind.User, username);

        public static TwoFactorTarget Admin(string username) => new(TwoFactorSubjectKind.Admin, username);
    }

    /// <summary>
    /// The second factor (#63) as the signed-in administrator may manage it (scoped per circuit). Every call resolves the
    /// target again and checks the permissions, so a page cannot do more than this class allows:
    /// <list type="bullet">
    /// <item>Its own account: every administrator sets up, renews the recovery codes of, and turns off its own second
    /// factor. Renewing and turning off need a current code (or a recovery code), so a taken-over session cannot remove
    /// it.</item>
    /// <item>An SFTP user: needs <see cref="AdminPermissions.ManageUsers"/> and the user in its scope
    /// (<see cref="AdminScopedSettingsRepository"/>). The administrator sets up the app for the user (the web client of
    /// #69 will let users do it themselves) and resets it.</item>
    /// <item>Another administrator: needs <see cref="AdminPermissions.ManageAdmins"/> and no more permissions than its
    /// own (like <see cref="AdminAdministrationService"/>); it can only reset (turn off) the second factor.</item>
    /// </list>
    /// Every change is a <see cref="ProviderEvent"/> with the changed field "TwoFactor", without the secret.
    /// </summary>
    public sealed class TwoFactorAdministration
    {
        public const string ChangedField = "TwoFactor";

        private readonly TwoFactorService _service;
        private readonly CurrentAdmin _current;
        private readonly IAdminStore _admins;
        private readonly AdminScopedSettingsRepository _users;
        private readonly IEventBus _events;
        private readonly TimeProvider _time;

        public TwoFactorAdministration(TwoFactorService service, CurrentAdmin current, IAdminStore admins,
            AdminScopedSettingsRepository users, IEventBus events, TimeProvider time)
        {
            _service = service;
            _current = current;
            _admins = admins;
            _users = users;
            _events = events;
            _time = time;
        }

        /// <summary>The account of the signed-in administrator.</summary>
        public TwoFactorTarget Self => TwoFactorTarget.Admin(_current.Actor.Username);

        /// <summary>True when the target is the signed-in administrator (its changes need a current code).</summary>
        public bool IsSelf(TwoFactorTarget target) =>
            target.Kind == TwoFactorSubjectKind.Admin && !string.IsNullOrEmpty(_current.Actor.Username)
            && string.Equals(target.Name, _current.Actor.Username, StringComparison.OrdinalIgnoreCase);

        /// <summary>True when the administrator may set up an app for the target (its own account or a user).</summary>
        public bool CanSetUp(TwoFactorTarget target) => target.Kind == TwoFactorSubjectKind.User || IsSelf(target);

        public async Task<TwoFactorStatus> GetStatusAsync(TwoFactorTarget target, CancellationToken ct)
        {
            var (subject, _) = await ResolveAsync(target, ct);
            return await _service.GetStatusAsync(subject, ct);
        }

        public async Task<TwoFactorSetup> BeginSetupAsync(TwoFactorTarget target, CancellationToken ct)
        {
            DemandSetUp(target);
            var (subject, name) = await ResolveAsync(target, ct);
            return await _service.BeginSetupAsync(subject, name, ct);
        }

        /// <summary>Turns the second factor on with a code of the app; returns the recovery codes, or null for a wrong code.</summary>
        public async Task<IReadOnlyList<string>> ConfirmSetupAsync(TwoFactorTarget target, string code, CancellationToken ct)
        {
            DemandSetUp(target);
            var (subject, name) = await ResolveAsync(target, ct);
            var codes = await _service.ConfirmSetupAsync(subject, code, ct);
            if (codes != null)
                await PublishAsync(target, name, ct);
            return codes;
        }

        public async Task<IReadOnlyList<string>> RegenerateRecoveryCodesAsync(TwoFactorTarget target, string currentCode, CancellationToken ct)
        {
            DemandSetUp(target);
            var (subject, name) = await ResolveAsync(target, ct);
            await DemandCodeOfSelfAsync(target, subject, currentCode, ct);
            var codes = await _service.RegenerateRecoveryCodesAsync(subject, ct);
            await PublishAsync(target, name, ct);
            return codes;
        }

        /// <summary>Turns the second factor of the target off (also an unconfirmed setup). False when it had none.</summary>
        public async Task<bool> ResetAsync(TwoFactorTarget target, string currentCode, CancellationToken ct)
        {
            var (subject, name) = await ResolveAsync(target, ct);
            var status = await _service.GetStatusAsync(subject, ct);
            if (status.State == TwoFactorState.On)
                await DemandCodeOfSelfAsync(target, subject, currentCode, ct);
            if (!await _service.ResetAsync(subject, ct))
                return false;
            if (status.State == TwoFactorState.On)
                await PublishAsync(target, name, ct);
            return true;
        }

        /// <summary>The ids of the users (or administrators) with a second factor, for the lists. Needs no extra permission: the lists filter by it.</summary>
        public Task<IReadOnlySet<int>> ListEnabledAsync(TwoFactorSubjectKind kind, CancellationToken ct)
        {
            if (string.IsNullOrEmpty(_current.Actor.Username))
                throw new AdminAccessDeniedException("You are not logged in.");
            return _service.ListEnabledAsync(kind, ct);
        }

        private void DemandSetUp(TwoFactorTarget target)
        {
            if (!CanSetUp(target))
                throw new AdminAccessDeniedException("An administrator sets up the second factor of its own account.");
        }

        private async Task DemandCodeOfSelfAsync(TwoFactorTarget target, TwoFactorSubject subject, string code, CancellationToken ct)
        {
            if (!IsSelf(target))
                return;
            var check = await _service.VerifyAsync(subject, code, ct);
            if (check is not (TwoFactorCheck.Valid or TwoFactorCheck.RecoveryCode))
                throw new AdminAccessDeniedException(check == TwoFactorCheck.LockedOut
                    ? "Too many wrong codes. Try again later."
                    : "Enter a current code of your authenticator app (or a recovery code).");
        }

        /// <summary>The subject and the stored name of the target, after the checks of the signed-in administrator.</summary>
        private async Task<(TwoFactorSubject Subject, string Name)> ResolveAsync(TwoFactorTarget target, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(target);
            var actor = _current.Actor;
            if (string.IsNullOrEmpty(actor.Username))
                throw new AdminAccessDeniedException("You are not logged in.");

            if (target.Kind == TwoFactorSubjectKind.User)
            {
                actor.Demand(AdminPermissions.ManageUsers);
                // The scoped repository returns only the users in the scope of the administrator.
                var user = _users.GetUser(target.Name)
                           ?? throw new AdminAdministrationException($"The user '{target.Name}' does not exist.");
                return (TwoFactorSubject.ForUser(user), user.Username);
            }

            if (!IsSelf(target))
                actor.Demand(AdminPermissions.ManageAdmins);
            var admin = await _admins.GetAdminAsync(target.Name, ct)
                        ?? throw new AdminAdministrationException($"The administrator '{target.Name}' does not exist.");
            if (!IsSelf(target) && (admin.Permissions & ~actor.Permissions) != AdminPermissions.None)
                throw new AdminAccessDeniedException($"The administrator '{admin.Username}' has permissions that you do not have.");
            return (TwoFactorSubject.ForAdmin(admin), admin.Username);
        }

        private async Task PublishAsync(TwoFactorTarget target, string name, CancellationToken ct)
        {
            var type = target.Kind == TwoFactorSubjectKind.User ? ProviderObjectType.User : ProviderObjectType.Admin;
            await _events.PublishAsync(new ProviderEvent(ProviderAction.Update, type, name)
            {
                Timestamp = _time.GetUtcNow(),
                Actor = _current.Actor.AuditName,
                ChangedFields = [ChangedField],
            }, ct);
        }
    }
}
