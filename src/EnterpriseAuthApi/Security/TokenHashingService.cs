using System.Security.Cryptography;

namespace EnterpriseAuthApi.Security;

public interface ITokenHashingService
{
    (string Hash, string Salt) HashToken(string token);
    bool Verify(string token, string hash, string salt);
}

public sealed class TokenHashingService : ITokenHashingService
{
    private const int SaltSize = 16;
    private const int KeySize = 32;
    private const int Iterations = 120_000;

    public (string Hash, string Salt) HashToken(string token)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(token, salt, Iterations, HashAlgorithmName.SHA512, KeySize);
        return (Convert.ToBase64String(hash), Convert.ToBase64String(salt));
    }

    public bool Verify(string token, string hash, string salt)
    {
        var expectedHash = Convert.FromBase64String(hash);
        var saltBytes = Convert.FromBase64String(salt);
        var actualHash = Rfc2898DeriveBytes.Pbkdf2(token, saltBytes, Iterations, HashAlgorithmName.SHA512, KeySize);
        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
    }
}
