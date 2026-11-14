using System.DirectoryServices.Protocols;
using System.Net;
using Microsoft.Extensions.Options;

namespace SshServer.Authentication.Ldap;

/// <summary>The connections of <see cref="LdapAuthenticationProvider"/> with System.DirectoryServices.Protocols.</summary>
public sealed class ProtocolsLdapConnector : ILdapConnector
{
    private const int InvalidCredentials = 49;
    private readonly LdapAuthenticationOptions _options;

    public ProtocolsLdapConnector(IOptions<LdapAuthenticationOptions> options)
    {
        _options = options.Value;
    }

    public ILdapSession Connect()
    {
        var timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds);
        try
        {
            var connection = new LdapConnection(new LdapDirectoryIdentifier(_options.Server, _options.EffectivePort))
            {
                AuthType = AuthType.Anonymous,
                Timeout = timeout,
            };
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            if (_options.UseTls)
                connection.SessionOptions.SecureSocketLayer = true;
            if (_options.StartTls)
            {
                try
                {
                    connection.SessionOptions.StartTransportLayerSecurity(null);
                }
                catch
                {
                    connection.Dispose();
                    throw;
                }
            }
            return new Session(connection, timeout);
        }
        catch (Exception ex) when (ex is LdapException or DirectoryOperationException or InvalidOperationException or PlatformNotSupportedException or DllNotFoundException)
        {
            throw new LdapDirectoryException($"The directory {_options.Server}:{_options.EffectivePort} cannot be reached: {ex.Message}", ex);
        }
    }

    private sealed class Session : ILdapSession
    {
        private readonly LdapConnection _connection;
        private readonly TimeSpan _timeout;

        public Session(LdapConnection connection, TimeSpan timeout)
        {
            _connection = connection;
            _timeout = timeout;
        }

        public bool Bind(string dn, string password)
        {
            try
            {
                _connection.AuthType = AuthType.Basic;
                _connection.Bind(new NetworkCredential(dn, password));
                return true;
            }
            catch (LdapException ex) when (ex.ErrorCode == InvalidCredentials)
            {
                return false;
            }
            catch (Exception ex) when (ex is LdapException or DirectoryOperationException or InvalidOperationException)
            {
                throw new LdapDirectoryException($"The bind failed: {ex.Message}", ex);
            }
        }

        public IReadOnlyList<LdapEntry> Search(string baseDn, string filter, bool subtree, IReadOnlyList<string> attributes)
        {
            try
            {
                var request = new SearchRequest(baseDn, filter, subtree ? SearchScope.Subtree : SearchScope.Base, attributes.ToArray());
                var response = (SearchResponse)_connection.SendRequest(request, _timeout);
                var result = new List<LdapEntry>();
                foreach (SearchResultEntry entry in response.Entries)
                {
                    var values = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
                    foreach (DirectoryAttribute attribute in entry.Attributes.Values)
                        values[attribute.Name] = attribute.GetValues(typeof(string)).Cast<string>().ToList();
                    result.Add(new LdapEntry(entry.DistinguishedName, values));
                }
                return result;
            }
            catch (DirectoryOperationException ex) when (ex.Response?.ResultCode == ResultCode.NoSuchObject)
            {
                return [];
            }
            catch (Exception ex) when (ex is LdapException or DirectoryOperationException or InvalidOperationException)
            {
                throw new LdapDirectoryException($"The search failed: {ex.Message}", ex);
            }
        }

        public void Dispose() => _connection.Dispose();
    }
}
