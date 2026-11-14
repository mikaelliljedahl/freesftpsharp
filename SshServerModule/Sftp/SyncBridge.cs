#nullable enable
using System.Threading.Tasks;

namespace SshServerModule.Sftp
{
    /// <summary>
    /// Waits for the asynchronous storage from the synchronous upstream SFTP engine (FxSsh <c>ISftpFileSystem</c>) and
    /// from the synchronous SSH events.
    /// <para>
    /// Why this does not deadlock: the engine handles the requests of a session in lanes (one per handle, one for the
    /// paths), inline in the receive loop of that session until a READ or WRITE goes asynchronous, then on the thread pool
    /// (no <see cref="System.Threading.SynchronizationContext"/> in the hosts). READ and WRITE of a file do not use this
    /// bridge (<c>ISftpAsyncFileHandle</c>, #133). The storage never needs that loop to complete: its continuations run on the thread pool, not on
    /// the blocked thread. Blocking the receive loop for one request is what the synchronous engine does with a
    /// synchronous file system too; the SSH window and keepalive wait for the same request.
    /// </para>
    /// <para>
    /// Cost: a call that completes synchronously (the local disk always does) is returned at once, without a task or a
    /// blocked thread. A call that really waits (a remote backend) blocks one thread pool thread per active session for
    /// the time of the call; with many sessions on a slow backend the pool grows. The way out is an asynchronous
    /// variant of <c>ISftpFileSystem</c> upstream (follow-up of #51).
    /// </para>
    /// </summary>
    internal static class SyncBridge
    {
        public static T Wait<T>(ValueTask<T> task)
            => task.IsCompletedSuccessfully ? task.Result : task.AsTask().GetAwaiter().GetResult();

        public static void Wait(ValueTask task)
        {
            if (task.IsCompletedSuccessfully)
                return;
            task.AsTask().GetAwaiter().GetResult();
        }
    }
}
