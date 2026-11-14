using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using SshServer.Interfaces.Security;

namespace SshServer.Filesystem.AzureBlob;

/// <summary>
/// The options of the Azure Blob storage ("azure-blob"): one container, or a key prefix in it, is "/" for the user.
/// Exactly one way to sign in is set: <see cref="ConnectionString"/>, <see cref="SasUrl"/> or <see cref="AccountName"/>
/// (a managed identity or another identity of <c>DefaultAzureCredential</c>). <see cref="ToString"/> never shows the
/// connection string or the SAS URL, and both are stored encrypted (<see cref="SecretAttribute"/>). The attributes
/// describe the fields of the admin UI.
/// </summary>
[DisplayName("Azure Blob Storage")]
[Description("A container, or a blob name prefix in it, of an Azure storage account (or Azurite).")]
public sealed record AzureBlobStorageOptions
{
    public const int MiB = 1024 * 1024;

    /// <summary>The smallest block that the server accepts as an upload block size.</summary>
    public const int MinUploadBlockSize = 64 * 1024;

    /// <summary>The largest block that the server buffers in memory.</summary>
    public const int MaxUploadBlockSize = 256 * MiB;

    public const int MaxUploadConcurrency = 64;
    public const int MinReadAheadSize = 64 * 1024;
    public const int MaxReadAheadSize = 512 * MiB;

    /// <summary>The container. It must exist; the server never creates or removes a container. Empty only with a <see cref="SasUrl"/> of the container.</summary>
    [Display(Name = "Container", Description = "The container must exist; the server never creates or removes a container.", Prompt = "files", Order = 1)]
    public string Container { get; init; } = string.Empty;

    /// <summary>The blob name prefix that is "/" for the user, for example "users/alice"; empty for the whole container.</summary>
    [Display(Name = "Prefix", Description = "The blob name prefix that is / for the client, for example users/alice. Empty: the whole container.", Prompt = "users/alice", Order = 2)]
    public string? KeyPrefix { get; init; }

    /// <summary>A connection string of the storage account (also "UseDevelopmentStorage=true" for Azurite). A secret.</summary>
    [Secret]
    [Display(Name = "Connection string", Description = "One way to sign in. It is stored encrypted and never shown again.", Order = 3)]
    public string? ConnectionString { get; init; }

    /// <summary>A SAS URL of the container (or of the account, with <see cref="Container"/>). A secret.</summary>
    [Secret]
    [Display(Name = "SAS URL", Description = "Or a SAS URL of the container. It is stored encrypted and never shown again.", Order = 4)]
    public string? SasUrl { get; init; }

    /// <summary>The storage account name: the server signs in with <c>DefaultAzureCredential</c> (managed identity, environment, Azure CLI).</summary>
    [Display(Name = "Account name", Description = "Or the account name, with the managed identity or another identity of the environment.", Order = 5)]
    public string? AccountName { get; init; }

    /// <summary>
    /// The blob service endpoint for <see cref="AccountName"/>, for example "https://myaccount.blob.core.chinacloudapi.cn"
    /// (a sovereign cloud) or "http://127.0.0.1:10000/devstoreaccount1" (Azurite). Empty: https://ACCOUNT.blob.core.windows.net.
    /// </summary>
    [Display(Name = "Endpoint", Description = "For the account name: a sovereign cloud or Azurite. Empty: https://ACCOUNT.blob.core.windows.net.", Order = 6)]
    public string? Endpoint { get; init; }

    /// <summary>The access tier of new blobs: "Hot", "Cool" or "Cold". Empty: the default of the account.</summary>
    [AllowedValues("", "Hot", "Cool", "Cold")]
    [Display(Name = "Access tier", Description = "Of new blobs. Empty: the default of the account.", Order = 7)]
    public string? AccessTier { get; init; }

    /// <summary>
    /// The size of one block of an upload, buffered in memory. A file can have at most 50,000 blocks, so the largest
    /// upload is 50,000 x this size (195 GiB with the default 4 MiB).
    /// </summary>
    [Display(Name = "Upload block size (bytes)", Description = "One block of an upload, buffered in memory. The largest file is 50,000 blocks.", Order = 8)]
    public int UploadBlockSize { get; init; } = 4 * MiB;

    /// <summary>The number of blocks of one upload that are sent at the same time.</summary>
    [Display(Name = "Upload concurrency", Description = "The blocks of one upload that are sent at the same time.", Order = 9)]
    public int UploadConcurrency { get; init; } = 2;

    /// <summary>The bytes that one read request fetches ahead, so a sequential download is one request per this size.</summary>
    [Display(Name = "Read-ahead size (bytes)", Description = "The bytes that one read request fetches ahead.", Order = 10)]
    public int ReadAheadSize { get; init; } = 4 * MiB;

    public override string ToString()
        => $"AzureBlobStorageOptions {{ Container = {Container}, KeyPrefix = {KeyPrefix}, " +
           $"ConnectionString = {(string.IsNullOrEmpty(ConnectionString) ? "" : "***")}, SasUrl = {(string.IsNullOrEmpty(SasUrl) ? "" : "***")}, " +
           $"AccountName = {AccountName}, Endpoint = {Endpoint}, AccessTier = {AccessTier}, UploadBlockSize = {UploadBlockSize}, " +
           $"UploadConcurrency = {UploadConcurrency}, ReadAheadSize = {ReadAheadSize} }}";
}
