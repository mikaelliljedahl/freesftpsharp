using SshServer.Interfaces.Storage;

namespace SshServer.Interfaces.Events;

/// <summary>The file operation of a <see cref="FileEvent"/>.</summary>
public enum FileEventType
{
    /// <summary>Before a file is opened for writing; a hook can refuse it (<see cref="IEventBus.AskAsync"/>).</summary>
    PreUpload,

    /// <summary>A file that was opened for writing is closed.</summary>
    Upload,

    /// <summary>Like <see cref="Upload"/>, for a file that did not exist before the upload.</summary>
    FirstUpload,

    /// <summary>Before a file is opened for reading; a hook can refuse it.</summary>
    PreDownload,

    /// <summary>A file that was opened for reading is closed.</summary>
    Download,

    /// <summary>Before a file is removed; a hook can refuse it.</summary>
    PreDelete,

    /// <summary>A file was removed.</summary>
    Delete,

    /// <summary>A file or directory was renamed.</summary>
    Rename,

    /// <summary>A directory was created.</summary>
    Mkdir,

    /// <summary>A directory was removed.</summary>
    Rmdir,

    /// <summary>A file was copied on the server.</summary>
    Copy,

    /// <summary>An SSH command ran.</summary>
    SshCommand,
}

/// <summary>The result of the operation of a <see cref="FileEvent"/>.</summary>
public enum FileEventStatus
{
    Ok,

    /// <summary>The storage refused or failed the operation; <see cref="FileEvent.Message"/> tells why.</summary>
    Error,

    /// <summary>A storage limit was reached.</summary>
    QuotaExceeded,

    /// <summary>A hook refused a <c>Pre*</c> event, so the operation did not run.</summary>
    Denied,
}

/// <summary>A file operation of a user, from the <c>EventingFileSystem</c> storage decorator.</summary>
/// <param name="Type">The operation.</param>
public sealed record FileEvent(FileEventType Type) : IEvent
{
    public EventCategory Category => EventCategory.File;

    public string TypeName => Type.ToString();

    public DateTimeOffset Timestamp { get; init; }

    public string Username { get; init; } = string.Empty;

    /// <summary>The virtual path, as the user sees it ("/" is the user root).</summary>
    public string VirtualPath { get; init; } = string.Empty;

    /// <summary>The new path of a <see cref="FileEventType.Rename"/> or <see cref="FileEventType.Copy"/>.</summary>
    public string? VirtualTargetPath { get; init; }

    /// <summary>The path in the storage backend, when the backend gives one. Null today.</summary>
    public string? BackendPath { get; init; }

    /// <summary>The name of the storage provider, for example "local".</summary>
    public string? Provider { get; init; }

    /// <summary>The size of the file in bytes: after an upload, the bytes read by a download, the size of a deleted file.</summary>
    public long? FileSize { get; init; }

    /// <summary>The time from the open to the close of a transfer, or the time of the operation.</summary>
    public TimeSpan? Elapsed { get; init; }

    public FileEventStatus Status { get; init; }

    /// <summary>Why the operation failed or was refused. It has only virtual paths.</summary>
    public string? Message { get; init; }

    /// <summary>The protocol, for example "SFTP".</summary>
    public string Protocol { get; init; } = string.Empty;

    /// <summary>The address of the client.</summary>
    public string? RemoteIp { get; init; }

    /// <summary>The session of the client, when the server tracks sessions (#57).</summary>
    public string? SessionId { get; init; }

    /// <summary>The open flags of an upload or download.</summary>
    public FileOpenFlags? OpenFlags { get; init; }

    /// <summary>More values for the consumers, for example from a protocol.</summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }

    /// <summary>True for the events that a hook can refuse.</summary>
    public bool IsPreEvent => Type is FileEventType.PreUpload or FileEventType.PreDownload or FileEventType.PreDelete;
}
