# AGENTS.md

Conventions for all contributors to this repository, human or AI agent.

For the project overview, features and usage samples, read [README.md](README.md).

For the structure of the code (plug-in points, storage backends, decorators), follow
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Every change must keep to these rules.

## Test-driven development

Use test-driven development (TDD) when it is practical:

1. Write a test that shows the bug or the new behaviour.
2. Run the test and make sure that it fails.
3. Change the production code until the test passes.
4. Refactor, and keep all tests green.

Be pragmatic. The repository has an automated test suite, so strict TDD is not
always necessary. Select the approach from the type of change:

| Type of change | Approach |
|---|---|
| Bug fix | TDD. First write a test that reproduces the bug. |
| Protocol or security behaviour (SFTP messages, path handling, authentication) | TDD. Tests must cover the specified behaviour and the failure cases. |
| New feature | TDD where the behaviour is testable. Otherwise, add tests together with the code. |
| Refactoring | Do not write new tests first. The existing suite must stay green before and after the change. |
| Dependency upgrades, build and CI changes, logging, documentation | No new tests are necessary. Run the full suite. |
| UI layout (Blazor/Radzen) | Tests are optional. Test the logic behind the UI if it changes. |

In all cases:

- Run the full test suite before you commit.
- Do not remove or weaken an existing test to make a change pass.
  If a test is wrong, fix the test in a separate commit and tell why.

## Tests

- The tests are in `tests/FreeSftpSharp.Tests` (xUnit). See `tests/README.md` for details.
- Run all tests from the repository root:

  ```bash
  dotnet test
  ```

- The end-to-end tests start the server in-process on a free port.
  They use SSH.NET and, if it is installed, the OpenSSH `sftp` client.

## Commits and pull requests

- Write commits, pull requests and issues in English.
- Make one pull request for each issue. Put `Closes #N` in the commit or pull request.
- CI (GitHub Actions) must be green on Linux and Windows before a merge.
