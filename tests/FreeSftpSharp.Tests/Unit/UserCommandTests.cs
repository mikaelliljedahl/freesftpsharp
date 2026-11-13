using FreeSftpSharp.Tests.Infrastructure;
using System.Security.Cryptography;
using FreeSftpSharp.Tests.Settings;
using FxSsh.SshServerModule.Cli;
using SshServer.Interfaces.Users;
using SshServer.Interfaces;
using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.Unit;

/// <summary><c>ServerConsoleApp user add|list|remove</c>: arguments, stdin password, output and exit codes.</summary>
public sealed class UserCommandTests : IDisposable
{
    private readonly TempDirectory _temp = new();
    private readonly InMemorySettingsRepository _repository = new(new ServerSettings());
    private readonly UserAdministrationService _service;

    public UserCommandTests() => _service = new UserAdministrationService(_repository);

    public void Dispose() => _temp.Dispose();

    private sealed record Result(int ExitCode, string Output, string Error);

    private Result Run(string stdin, bool interactive, string[] hiddenAnswers, params string[] args)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var answers = new Queue<string>(hiddenAnswers);
        var code = UserCommand.Run(["user", .. args], _service, new StringReader(stdin), output, error, interactive,
            prompt => answers.Dequeue());
        return new Result(code, output.ToString(), error.ToString());
    }

    private Result Run(string stdin, params string[] args) => Run(stdin, false, [], args);

    [Fact]
    public void Is_requested_only_for_the_user_command()
    {
        Assert.True(UserCommand.IsRequested(["user", "list"]));
        Assert.True(UserCommand.IsRequested(["USER"]));
        Assert.False(UserCommand.IsRequested([]));
        Assert.False(UserCommand.IsRequested(["--port", "2222"]));
    }

    [Fact]
    public void Add_reads_the_password_from_stdin_and_stores_a_hash()
    {
        var root = _temp.File("root");

        var result = Run("my secret pw\r\nignored\n", "add", "alice", "--root", root, "--password-stdin");

        Assert.Equal(0, result.ExitCode);
        var user = _repository.GetUser("alice");
        Assert.True(PasswordHasher.Verify("my secret pw", user.HashedPassword));
        Assert.Equal(root, user.UserRootDirectory);
        Assert.DoesNotContain("my secret pw", result.Output + result.Error);
        Assert.DoesNotContain(user.HashedPassword, result.Output + result.Error);
    }

    [Fact]
    public void Add_creates_a_missing_root_directory()
    {
        var root = _temp.File("not/there/yet");

        var result = Run("my secret pw\n", "add", "alice", "--root", root, "--password-stdin");

        Assert.Equal(0, result.ExitCode);
        Assert.True(Directory.Exists(root));
    }

    [Fact]
    public void Add_accepts_root_with_an_equals_sign()
    {
        var result = Run("my secret pw\n", "add", "alice", $"--root={_temp.File("r")}", "--password-stdin");

        Assert.Equal(0, result.ExitCode);
        Assert.NotNull(_repository.GetUser("alice"));
    }

    [Fact]
    public void Add_prompts_twice_without_echo_when_stdin_is_a_terminal()
    {
        var result = Run("", true, ["typed password", "typed password"], "add", "alice", "--root", _temp.File("r"));

        Assert.Equal(0, result.ExitCode);
        Assert.True(PasswordHasher.Verify("typed password", _repository.GetUser("alice").HashedPassword));
    }

    [Fact]
    public void Add_fails_when_the_prompted_passwords_differ()
    {
        var result = Run("", true, ["typed password", "another one"], "add", "alice", "--root", _temp.File("r"));

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("do not match", result.Error);
        Assert.Null(_repository.GetUser("alice"));
    }

    [Fact]
    public void Add_without_a_credential_and_without_a_terminal_is_a_usage_error()
    {
        var result = Run("", "add", "alice", "--root", _temp.File("r"));

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("--password-stdin", result.Error);
        Assert.Null(_repository.GetUser("alice"));
    }

    [Fact]
    public void Add_with_a_public_key_file_stores_the_key_and_no_password()
    {
        using var rsa = RSA.Create(2048);
        var keyFile = _temp.File("id_rsa.pub");
        File.WriteAllText(keyFile, UserAdministrationServiceTests.ToOpenSshLine(rsa.ExportParameters(false), "me") + "\n");

        var result = Run("", "add", "keyuser", "--root", _temp.File("r"), "--public-key", keyFile);

        Assert.Equal(0, result.ExitCode);
        var user = _repository.GetUser("keyuser");
        Assert.Null(user.HashedPassword);
        Assert.False(string.IsNullOrEmpty(user.RsaPublicKey));
    }

    [Fact]
    public void Add_with_a_missing_public_key_file_fails()
    {
        var result = Run("", "add", "keyuser", "--root", _temp.File("r"), "--public-key", _temp.File("nope.pub"));

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("cannot be read", result.Error);
        Assert.Null(_repository.GetUser("keyuser"));
    }

    [Fact]
    public void Add_with_both_password_and_key_is_a_usage_error()
    {
        var result = Run("my secret pw\n", "add", "alice", "--root", _temp.File("r"), "--password-stdin", "--public-key", _temp.File("k.pub"));

        Assert.Equal(2, result.ExitCode);
        Assert.Null(_repository.GetUser("alice"));
    }

    [Theory]
    [InlineData("add", "--root", "x", "--password-stdin")]           // no name
    [InlineData("add", "alice", "--password-stdin")]                  // no root
    [InlineData("add", "alice", "--root")]                            // root without value
    [InlineData("add", "alice", "bob", "--root", "x")]                // two names
    [InlineData("add", "alice", "--root", "x", "--password", "pw")]   // a password argument does not exist
    [InlineData("list", "extra")]
    [InlineData("remove")]
    [InlineData("remove", "a", "b")]
    [InlineData("frobnicate")]
    public void Wrong_usage_gives_exit_code_2_and_the_usage_text(params string[] args)
    {
        var result = Run("my secret pw\n", args);

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("Usage:", result.Error);
        Assert.Empty(_repository.GetAllUsers());
    }

    [Fact]
    public void No_command_after_user_is_a_usage_error()
    {
        var result = Run("");
        Assert.Equal(2, result.ExitCode);
    }

    [Theory]
    [InlineData("bad name", "my secret pw", "name")]
    [InlineData("alice", "short", "at least 8")]
    public void Bad_input_gives_exit_code_1_with_a_message_and_stores_nothing(string name, string password, string expected)
    {
        var result = Run(password + "\n", "add", name, "--root", _temp.File("r"), "--password-stdin");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains(expected, result.Error);
        Assert.Empty(_repository.GetAllUsers());
    }

    [Fact]
    public void Add_with_empty_stdin_fails()
    {
        var result = Run("", "add", "alice", "--root", _temp.File("r"), "--password-stdin");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("No password", result.Error);
    }

    [Fact]
    public void Add_of_a_duplicate_name_fails_in_any_letter_case_and_keeps_the_first_user()
    {
        Run("my secret pw\n", "add", "Alice", "--root", _temp.File("r1"), "--password-stdin");

        var result = Run("another secret\n", "add", "alice", "--root", _temp.File("r2"), "--password-stdin");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("already exists", result.Error);
        var only = Assert.Single(_repository.GetAllUsers());
        Assert.True(PasswordHasher.Verify("my secret pw", only.HashedPassword));
    }

    [Fact]
    public void List_shows_names_login_kinds_and_roots_but_never_secrets()
    {
        Run("my secret pw\n", "add", "alice", "--root", _temp.File("ra"), "--password-stdin");
        using var rsa = RSA.Create(2048);
        var keyFile = _temp.File("k.pub");
        File.WriteAllText(keyFile, UserAdministrationServiceTests.ToOpenSshLine(rsa.ExportParameters(false), "me"));
        Run("", "add", "bob", "--root", _temp.File("rb"), "--public-key", keyFile);

        var result = Run("", "list");

        Assert.Equal(0, result.ExitCode);
        var alice = result.Output.Split('\n').Single(l => l.StartsWith("alice"));
        var bob = result.Output.Split('\n').Single(l => l.StartsWith("bob"));
        Assert.Contains("password", alice);
        Assert.Contains(_temp.File("ra"), alice);
        Assert.Contains("key", bob);
        Assert.DoesNotContain("password", bob);
        Assert.DoesNotContain("PBKDF2", result.Output);
        Assert.DoesNotContain(_repository.GetUser("bob").RsaPublicKey, result.Output);
    }

    [Fact]
    public void List_of_an_empty_database_says_so_and_succeeds()
    {
        var result = Run("", "list");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("No users", result.Output);
    }

    [Fact]
    public void Remove_deletes_the_user_in_any_letter_case_and_keeps_the_files()
    {
        Run("my secret pw\n", "add", "Alice", "--root", _temp.File("r"), "--password-stdin");

        var result = Run("", "remove", "alice");

        Assert.Equal(0, result.ExitCode);
        Assert.Empty(_repository.GetAllUsers());
        Assert.True(Directory.Exists(_temp.File("r")));
    }

    [Fact]
    public void Remove_of_an_unknown_user_fails()
    {
        var result = Run("", "remove", "ghost");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("does not exist", result.Error);
    }
}
