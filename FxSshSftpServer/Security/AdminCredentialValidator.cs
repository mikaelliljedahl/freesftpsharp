using System;
using Microsoft.Extensions.Options;

namespace FxSshSftpServer.Security
{
    public sealed class AdminCredentialValidator
    {
        private readonly IOptions<AdminAuthOptions> _options;

        public AdminCredentialValidator(IOptions<AdminAuthOptions> options)
        {
            _options = options;
        }

        public bool IsConfigured => _options.Value.IsConfigured;

        public string UserName => _options.Value.UserName?.Trim();

        public bool Validate(string userName, string password)
        {
            var options = _options.Value;
            if (!options.IsConfigured)
                return false;

            var userMatches = string.Equals(userName?.Trim(), options.UserName.Trim(), StringComparison.OrdinalIgnoreCase);
            if (!userMatches)
            {
                // Same cost as a real check, so the response time does not tell whether the user name exists.
                AdminPasswordHasher.BurnEquivalentWork(options.PasswordHash);
                return false;
            }

            return AdminPasswordHasher.Verify(password ?? "", options.PasswordHash);
        }
    }
}
