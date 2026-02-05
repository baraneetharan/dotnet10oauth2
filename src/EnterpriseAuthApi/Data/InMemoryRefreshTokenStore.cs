using System.Collections.Concurrent;
using EnterpriseAuthApi.Models;

namespace EnterpriseAuthApi.Data;

public interface IRefreshTokenStore
{
    Task AddAsync(RefreshTokenRecord token, CancellationToken cancellationToken);
    Task<RefreshTokenRecord?> FindByTokenAsync(string plaintextToken, Func<RefreshTokenRecord, bool> verifier, CancellationToken cancellationToken);
    Task<RefreshTokenRecord?> GetByIdAsync(Guid id, CancellationToken cancellationToken);
    Task UpdateAsync(RefreshTokenRecord token, CancellationToken cancellationToken);
    Task<IReadOnlyList<RefreshTokenRecord>> GetByFamilyIdAsync(string familyId, CancellationToken cancellationToken);
}

public sealed class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly ConcurrentDictionary<Guid, RefreshTokenRecord> _tokens = new();

    public Task AddAsync(RefreshTokenRecord token, CancellationToken cancellationToken)
    {
        _tokens[token.Id] = token;
        return Task.CompletedTask;
    }

    public Task<RefreshTokenRecord?> FindByTokenAsync(string plaintextToken, Func<RefreshTokenRecord, bool> verifier, CancellationToken cancellationToken)
    {
        var token = _tokens.Values.FirstOrDefault(verifier);
        return Task.FromResult(token);
    }

    public Task<RefreshTokenRecord?> GetByIdAsync(Guid id, CancellationToken cancellationToken)
    {
        _tokens.TryGetValue(id, out var token);
        return Task.FromResult(token);
    }

    public Task UpdateAsync(RefreshTokenRecord token, CancellationToken cancellationToken)
    {
        _tokens[token.Id] = token;
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<RefreshTokenRecord>> GetByFamilyIdAsync(string familyId, CancellationToken cancellationToken)
    {
        var family = _tokens.Values.Where(t => t.FamilyId == familyId).ToList();
        return Task.FromResult<IReadOnlyList<RefreshTokenRecord>>(family);
    }
}
