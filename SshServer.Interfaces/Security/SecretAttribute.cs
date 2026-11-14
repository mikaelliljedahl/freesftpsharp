namespace SshServer.Interfaces.Security;

/// <summary>
/// Marks a string property of a storage options record as a secret (for example an S3 secret key). The settings store
/// keeps it encrypted (<see cref="ISecretProtector"/>), and the admin UI, the API and the logs never show it.
/// </summary>
[AttributeUsage(AttributeTargets.Property, Inherited = true)]
public sealed class SecretAttribute : Attribute
{
}
