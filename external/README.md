# Vendored libraries

## FxSsh (`external/FxSsh`)

[Aimeast/FxSsh](https://github.com/Aimeast/FxSsh), vendored with `git subtree --squash` from branch `dev`
at commit `cd35224` (`fix: release forwarded sockets rejected before the bridge subscribed`). License: MIT,
see `external/FxSsh/LICENSE.md`.

Only the library project `external/FxSsh/FxSsh/FxSsh.csproj` is in `FreeSftpSharp.sln`. The upstream test
projects (`FxSsh.Tests`, `FxSsh.IntegrationTests`, MSTest) and `SshServerLoader` are not built by our
solution. `external/FxSsh/global.json` only applies to `dotnet` commands that run inside `external/FxSsh`.

### Local patches

None. The directory is identical to upstream `cd35224`. Keep it that way if possible: put our code in
`SshServerModule`, and send fixes upstream. If a local patch is necessary, make it in a separate commit
after the subtree commit and list it here, so that the next `git subtree pull` can check it.

### Update

```sh
git subtree pull --prefix=external/FxSsh https://github.com/Aimeast/FxSsh.git dev --squash
```

Then build and run the full test suite. Upstream targets the newest .NET (net11.0 at `cd35224`); our
projects must target the same version or newer.
