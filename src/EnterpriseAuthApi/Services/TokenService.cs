using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using EnterpriseAuthApi.Configuration;
using EnterpriseAuthApi.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace EnterpriseAuthApi.Services;

public interface ITokenService
{
    (string AccessToken, DateTimeOffset ExpiresAtUtc, string Jti) CreateAccessToken(AppUser user);
    string CreateOpaqueRefreshToken();
}

public sealed class TokenService : ITokenService
{
    private readonly JwtOptions _jwtOptions;
    private readonly SigningCredentials _signingCredentials;

    public TokenService(IOptions<JwtOptions> jwtOptions)
    {
        _jwtOptions = jwtOptions.Value;

        if (_jwtOptions.SigningKey.Length < 64)
        {
            throw new InvalidOperationException("JWT signing key must be at least 64 characters for HMAC SHA-512.");
        }

        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.SigningKey));
        _signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha512);
    }

    public (string AccessToken, DateTimeOffset ExpiresAtUtc, string Jti) CreateAccessToken(AppUser user)
    {
        var now = DateTimeOffset.UtcNow;
        var expires = now.AddMinutes(_jwtOptions.AccessTokenMinutes);
        var jti = Guid.NewGuid().ToString("N");

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.UniqueName, user.Username),
            new(JwtRegisteredClaimNames.Jti, jti),
            new("department", user.Department),
            new("mfa", user.MfaEnrolled ? "true" : "false")
        };

        claims.AddRange(user.Roles.Select(role => new Claim(ClaimTypes.Role, role)));
        claims.AddRange(user.Permissions.Select(permission => new Claim("permission", permission)));

        var token = new JwtSecurityToken(
            issuer: _jwtOptions.Issuer,
            audience: _jwtOptions.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expires.UtcDateTime,
            signingCredentials: _signingCredentials);

        return (new JwtSecurityTokenHandler().WriteToken(token), expires, jti);
    }

    public string CreateOpaqueRefreshToken()
    {
        var random = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(random);
    }
}
