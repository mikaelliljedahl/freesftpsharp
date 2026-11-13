using System;
using System.Collections.Generic;
using System.Linq;

namespace FxSshSftpServer.Components.Shared
{
    public enum ToastLevel
    {
        Success,
        Error,
        Warning,
        Info,
    }

    public sealed record ToastMessage(Guid Id, ToastLevel Level, string Text);

    /// <summary>Short messages for saved and failed actions. One instance per circuit (scoped); <see cref="ToastHost"/> shows them.</summary>
    public sealed class ToastService
    {
        private readonly List<ToastMessage> _messages = new();

        public event Action Changed;

        public IReadOnlyList<ToastMessage> Messages
        {
            get
            {
                lock (_messages)
                    return _messages.ToList();
            }
        }

        public void ShowSuccess(string text) => Show(ToastLevel.Success, text);

        public void ShowError(string text) => Show(ToastLevel.Error, text);

        public void ShowWarning(string text) => Show(ToastLevel.Warning, text);

        public ToastMessage Show(ToastLevel level, string text)
        {
            var message = new ToastMessage(Guid.NewGuid(), level, text);
            lock (_messages)
                _messages.Add(message);
            Changed?.Invoke();
            return message;
        }

        public void Dismiss(Guid id)
        {
            lock (_messages)
                _messages.RemoveAll(m => m.Id == id);
            Changed?.Invoke();
        }
    }
}
