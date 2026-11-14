namespace SshServer.Webhooks;

/// <summary>Wakes the <see cref="WebhookDispatcher"/> when the sink or the admin UI added a delivery.</summary>
public sealed class WebhookDispatchSignal
{
    private TaskCompletionSource _signal = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Completes at the next <see cref="Notify"/> after the last <see cref="Reset"/>.</summary>
    public Task WaitTask => Volatile.Read(ref _signal).Task;

    public void Notify() => Volatile.Read(ref _signal).TrySetResult();

    /// <summary>Starts a new wait, if the current one has completed.</summary>
    public void Reset()
    {
        var current = Volatile.Read(ref _signal);
        if (current.Task.IsCompleted)
            Interlocked.CompareExchange(ref _signal, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously), current);
    }
}
