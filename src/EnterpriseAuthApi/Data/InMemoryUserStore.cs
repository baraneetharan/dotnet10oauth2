using EnterpriseAuthApi.Models;
using EnterpriseAuthApi.Security;

namespace EnterpriseAuthApi.Data;

public interface IUserStore
{
    AppUser? GetByUsername(string username);
    AppUser? GetById(Guid userId);
    bool UsernameExists(string username);
    AppUser Create(string username, string passwordHash, string department);
}

public sealed class InMemoryUserStore : IUserStore
{
    private readonly Dictionary<string, AppUser> _users;
    private readonly Lock _sync = new();

    public InMemoryUserStore(IPasswordHasher passwordHasher)
    {
        _users = new(StringComparer.OrdinalIgnoreCase)
        {
            ["admin"] = new AppUser(
                Guid.Parse("11111111-1111-1111-1111-111111111111"),
                "admin",
                passwordHasher.HashPassword("Admin!ChangeMe1"),
                "Security",
                ["Administrator"],
                ["users:manage", "finance:read", "finance:write", "hr:read"],
                true),
            ["analyst"] = new AppUser(
                Guid.Parse("22222222-2222-2222-2222-222222222222"),
                "analyst",
                passwordHasher.HashPassword("Analyst!ChangeMe1"),
                "Finance",
                ["Analyst"],
                ["finance:read"],
                false)
        };
    }

    public AppUser? GetByUsername(string username)
    {
        lock (_sync)
        {
            return _users.GetValueOrDefault(username);
        }
    }

    public AppUser? GetById(Guid userId)
    {
        lock (_sync)
        {
            return _users.Values.FirstOrDefault(u => u.Id == userId);
        }
    }

    public bool UsernameExists(string username)
    {
        lock (_sync)
        {
            return _users.ContainsKey(username);
        }
    }

    public AppUser Create(string username, string passwordHash, string department)
    {
        lock (_sync)
        {
            if (_users.ContainsKey(username))
            {
                throw new InvalidOperationException("Username already exists.");
            }

            var user = new AppUser(
                Guid.NewGuid(),
                username,
                passwordHash,
                department,
                ["Employee"],
                ["finance:read"],
                false);

            _users[username] = user;
            return user;
        }
    }
}
