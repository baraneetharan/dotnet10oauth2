using EnterpriseAuthApi.Configuration;
using EnterpriseAuthApi.Data;
using EnterpriseAuthApi.Models;
using EnterpriseAuthApi.Security;
using Microsoft.Extensions.Options;

namespace EnterpriseAuthApi.Services;

public interface IRefreshTokenService
{
    Task<(RefreshTokenRecord Record, string PlaintextToken)> CreateAsync(AppUser user, string? familyId, Guid? parentTokenId, HttpContext httpContext, CancellationToken cancellationToken);
    Task<(bool Success, RefreshTokenRecord? ExistingToken, string Error)> TryFindAsync(string plaintextToken, CancellationToken cancellationToken);
    Task RevokeFamilyAsync(string familyId, string reason, CancellationToken cancellationToken);
}

public sealed class RefreshTokenService : IRefreshTokenService
{
    private readonly IRefreshTokenStore _refreshTokenStore;
    private readonly ITokenService _tokenService;
    private readonly ITokenHashingService _tokenHashingService;
    private readonly RefreshTokenOptions _options;

    public RefreshTokenService(
        IRefreshTokenStore refreshTokenStore,
        ITokenService tokenService,
        ITokenHashingService tokenHashingService,
        IOptions<RefreshTokenOptions> options)
    {
        _refreshTokenStore = refreshTokenStore;
        _tokenService = tokenService;
        _tokenHashingService = tokenHashingService;
        _options = options.Value;
    }

    public async Task<(RefreshTokenRecord Record, string PlaintextToken)> CreateAsync(AppUser user, string? familyId, Guid? parentTokenId, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var plaintext = _tokenService.CreateOpaqueRefreshToken();
        var (hash, salt) = _tokenHashingService.HashToken(plaintext);
        var now = DateTimeOffset.UtcNow;

        var record = new RefreshTokenRecord
        {
            UserId = user.Id,
            FamilyId = familyId ?? Guid.NewGuid().ToString("N"),
            ParentTokenId = parentTokenId,
            TokenHash = hash,
            TokenSalt = salt,
            CreatedAtUtc = now,
            ExpiresAtUtc = now.AddDays(_options.LifetimeDays),
            AbsoluteExpiresAtUtc = now.AddDays(_options.AbsoluteLifetimeDays),
            CreatedByIpAddress = httpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent = httpContext.Request.Headers.UserAgent.ToString()
        };

        await _refreshTokenStore.AddAsync(record, cancellationToken);
        return (record, plaintext);
    }

    public async Task<(bool Success, RefreshTokenRecord? ExistingToken, string Error)> TryFindAsync(string plaintextToken, CancellationToken cancellationToken)
    {
        var token = await _refreshTokenStore.FindByTokenAsync(
            plaintextToken,
            record => _tokenHashingService.Verify(plaintextToken, record.TokenHash, record.TokenSalt),
            cancellationToken);

        if (token is null)
        {
            return (false, null, "Invalid refresh token.");
        }

        if (DateTimeOffset.UtcNow >= token.AbsoluteExpiresAtUtc)
        {
            return (false, token, "Refresh token absolute lifetime exceeded.");
        }

        return (true, token, string.Empty);
    }

    public async Task RevokeFamilyAsync(string familyId, string reason, CancellationToken cancellationToken)
    {
        var family = await _refreshTokenStore.GetByFamilyIdAsync(familyId, cancellationToken);
        var now = DateTimeOffset.UtcNow;

        foreach (var token in family.Where(t => t.RevokedAtUtc is null))
        {
            token.RevokedAtUtc = now;
            token.RevocationReason = reason;
            await _refreshTokenStore.UpdateAsync(token, cancellationToken);
        }
    }
}
