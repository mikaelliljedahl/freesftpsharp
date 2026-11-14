# Encrypted local storage

The storage provider `local-encrypted` (project `SshServer.Filesystem.Encrypted`) stores the file contents of the user
roots encrypted on the local disk. A stolen disk, a backup or another account on the host that has the files but not
the key cannot read them. A changed, cut or reordered file gives an error (SFTP `SSH_FX_FAILURE`), never wrong data.

What stays in the clear: file and directory names, the directory structure, the times, the permissions and the file
sizes (the plaintext size follows from the file length).

## Turn it on

The encrypted storage is off by default; nothing changes and nothing is required while it is off. Until the per-user
storage configuration (#56) exists, one switch applies to **every** user root.

```json
{
  "Storage": {
    "Encryption": {
      "Enabled": true,
      "ActiveKeyId": "2026-01",
      "Keys": [
        { "Id": "2026-01", "KeyFile": "/etc/freesftpsharp/2026-01.key" }
      ]
    }
  }
}
```

| Key | Meaning |
| --- | --- |
| `Storage:Encryption:Enabled` | `true` stores every user root encrypted. Default `false` |
| `Storage:Encryption:ActiveKeyId` | The id of the key that encrypts new files |
| `Storage:Encryption:Keys:N:Id` | A name of the key. The file header stores a hash of it, so never rename a key |
| `Storage:Encryption:Keys:N:Key` | The key: base64 of 32 random bytes. Use an environment variable (`Storage__Encryption__Keys__0__Key`) or user secrets, not `appsettings.json` |
| `Storage:Encryption:Keys:N:KeyFile` | Or a file with the base64 key. On Linux and macOS only the owner may read it (`chmod 600`) |

Make a key:

```sh
umask 077 && openssl rand -base64 32 > /etc/freesftpsharp/2026-01.key
```

When `Enabled` is `true`, the server does not start if the active key is missing, has the wrong length, is not
base64, or its key file can be read by other users. The message names the key id and the problem, never the key.
The keys are never logged.

**Use new, empty user root directories.** Files that were stored before the switch are not encrypted and cannot be
read through the encrypted storage. There is no tool that encrypts an existing directory; copy the files in through
SFTP instead.

**Keep the keys safe.** Without the key the files are lost. Back up the keys separately from the files.

## Key rotation

1. Add a new key to `Keys` and make it the `ActiveKeyId`. Keep the old key in the list.
2. New files are encrypted with the new key; old files are still read with the old key (the header names its key).
3. To retire the old key, write the old files again (download and upload), then remove the old key.

A later issue can add a key vault or a cloud KMS by implementing `IMasterKeyProvider`; the file format does not change.

## Limits

The format writes each file once, from the start to the end. These operations answer `SSH_FX_OP_UNSUPPORTED`, and the
backend does not declare `StorageCapabilities.RandomAccessWrite` and `StorageCapabilities.Append`:

- a write at an offset other than the end of the data written by this handle (random-access write, resume of an upload);
- a write to an existing file that was not opened with truncate, and append;
- a change of the size (truncate, SETSTAT size).

Changing a chunk in place would encrypt new data with a nonce that was used before, which breaks AES-GCM. Uploads with
OpenSSH `sftp` and SSH.NET write sequentially and work. A client that resumes an upload or writes in place gets
the error.

`fsync` writes every complete 64 KiB chunk to the disk; the last, incomplete chunk is written when the file is closed.

The file key does not depend on the path, so rename is cheap. It also means that someone with write access to the disk
can swap two whole encrypted files or replace a file with an older version of itself; this is not detected (the same
holds for SFTPGo's cryptfs).

## File format v1

All integers are big-endian.

```
header (53 bytes):  "FSS1" (4) | version 0x01 (1) | key id (16) | file salt (32, random per file)
chunk i (i = 0, 1, ...):
    ciphertext || tag (16) = AES-256-GCM(key   = fileKey,
                                         nonce = salt[0..8] || uint32(i),
                                         aad   = header || uint32(i),
                                         plaintext = up to 65536 bytes)
fileKey = HKDF-SHA256(ikm = master key, salt = file salt, info = "freesftpsharp-dare-v1", length 32)
key id  = SHA-256(UTF-8 of the configured key id)[0..16]
```

- Every chunk except the last has exactly 65536 bytes of plaintext. The last chunk always has fewer, so a file whose
  plaintext size is a multiple of 65536 (also an empty file) ends with an empty chunk: only its 16 byte tag.
- File length = 53 + floor(n / 65536) * 65552 + (n mod 65536) + 16 for n plaintext bytes. A length that does not have
  this form (for example a file cut at a chunk boundary) is damaged.
- The chunk index in the nonce and in the associated data detects reordered chunks and chunks of other files; the
  short last chunk detects a cut file. The header is part of the associated data, so a changed header byte is detected
  too.
- Version 1 is AES-256-GCM only (.NET `AesGcm`, which uses AES-NI where the CPU has it). A ChaCha20-Poly1305 variant
  would get another version byte.
- The file key is never stored. The random salt gives every file (and every new version of a file) its own key.

The known-answer vectors in `tests/FreeSftpSharp.Tests/Storage/Encrypted/EncryptedFileFormatTests.cs` fix the format.
They were made with an independent implementation, not with this code. A change of the format needs a new version byte.
