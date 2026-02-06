namespace EnterpriseAuthApi.Data;

/// <summary>
/// Tracks revoked access tokens and users with revoked sessions.
/// In production, this should use a distributed cache (Redis) for scale-out scenarios.
/// </summary>
public interface ITokenRevocationStore
{
    Task RevokeUserAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<bool> IsUserRevokedAsync(Guid userId, CancellationToken cancellationToken = default);
    Task RevokeTokenAsync(string jti, DateTimeOffset expiresAtUtc, CancellationToken cancellationToken = default);
    Task<bool> IsTokenRevokedAsync(string jti, CancellationToken cancellationToken = default);
}

public sealed class InMemoryTokenRevocationStore : ITokenRevocationStore
{
    private readonly Dictionary<Guid, DateTimeOffset> _revokedUsers = new();
    private readonly Dictionary<string, DateTimeOffset> _revokedTokens = new();
    private readonly object _lock = new();
    private Timer? _cleanupTimer;

    public InMemoryTokenRevocationStore()
    {
        // Cleanup expired entries every 5 minutes
        _cleanupTimer = new Timer(_ => CleanupExpiredEntries(), null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
    }

    public Task RevokeUserAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            _revokedUsers[userId] = DateTimeOffset.UtcNow.AddHours(24); // Store for 24 hours
        }

        return Task.CompletedTask;
    }

    public Task<bool> IsUserRevokedAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            if (!_revokedUsers.TryGetValue(userId, out var revokedUntilUtc))
            {
                return Task.FromResult(false);
            }

            // If revocation period has expired, remove it
            if (DateTimeOffset.UtcNow >= revokedUntilUtc)
            {
                _revokedUsers.Remove(userId);
                return Task.FromResult(false);
            }

            return Task.FromResult(true);
        }
    }

    public Task RevokeTokenAsync(string jti, DateTimeOffset expiresAtUtc, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            _revokedTokens[jti] = expiresAtUtc;
        }

        return Task.CompletedTask;
    }

    public Task<bool> IsTokenRevokedAsync(string jti, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            if (!_revokedTokens.TryGetValue(jti, out var expiresAtUtc))
            {
                return Task.FromResult(false);
            }

            // If token has expired, remove it and consider it not revoked
            if (DateTimeOffset.UtcNow >= expiresAtUtc)
            {
                _revokedTokens.Remove(jti);
                return Task.FromResult(false);
            }

            return Task.FromResult(true);
        }
    }

    private void CleanupExpiredEntries()
    {
        lock (_lock)
        {
            var now = DateTimeOffset.UtcNow;
            
            var expiredUsers = _revokedUsers
                .Where(kvp => now >= kvp.Value)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var userId in expiredUsers)
            {
                _revokedUsers.Remove(userId);
            }

            var expiredTokens = _revokedTokens
                .Where(kvp => now >= kvp.Value)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var jti in expiredTokens)
            {
                _revokedTokens.Remove(jti);
            }
        }
    }
}
