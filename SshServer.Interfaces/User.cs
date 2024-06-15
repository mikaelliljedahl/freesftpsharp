namespace SshServer.Interfaces;



/// <summary>
/// Either provide Password or Key for login
/// </summary>
/// <value></value>
public class User
{
    public int Id { get; set; }
    public string Username { get; set; }
    public string UserRootDirectory { get; set; }
    public string HashedPassword { get; set; }
    public string RsaPublicKey { get; set; }
    public bool OnlyWhitelistedIps { get; set; }
    public List<string> WhitelistedIps { get; set; }
    public DateTime LastSuccessfulLogin { get; set; }

}