using System.Security.Claims;
using System.Text;
using EnterpriseAuthApi.Authorization;
using EnterpriseAuthApi.Configuration;
using EnterpriseAuthApi.Data;
using EnterpriseAuthApi.Models;
using EnterpriseAuthApi.Security;
using EnterpriseAuthApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.SectionName));
builder.Services.Configure<RefreshTokenOptions>(builder.Configuration.GetSection(RefreshTokenOptions.SectionName));

var jwtOptions = builder.Configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>()
    ?? throw new InvalidOperationException("JWT configuration is missing.");

if (jwtOptions.SigningKey.Length < 64)
{
    throw new InvalidOperationException("JWT signing key must be at least 64 characters.");
}

var signingKeyBytes = Encoding.UTF8.GetBytes(jwtOptions.SigningKey);

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = true;
        options.SaveToken = false;
        options.IncludeErrorDetails = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes),
            ClockSkew = TimeSpan.FromSeconds(jwtOptions.ClockSkewSeconds),
            NameClaimType = ClaimTypes.Name,
            RoleClaimType = ClaimTypes.Role
        };

        options.Events = new JwtBearerEvents
        {
            OnChallenge = context =>
            {
                context.Response.Headers.Append("WWW-Authenticate", "Bearer error=\"invalid_token\"");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(Policies.AddEnterprisePolicies);

builder.Services.AddSingleton<IPasswordHasher, PasswordHasher>();
builder.Services.AddSingleton<ITokenHashingService, TokenHashingService>();
builder.Services.AddSingleton<IUserStore, InMemoryUserStore>();
builder.Services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
builder.Services.AddSingleton<ITokenService, TokenService>();
builder.Services.AddSingleton<IRefreshTokenService, RefreshTokenService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/auth/login", async (
    [FromBody] LoginRequest request,
    IUserStore userStore,
    IPasswordHasher passwordHasher,
    ITokenService tokenService,
    IRefreshTokenService refreshTokenService,
    HttpContext httpContext,
    CancellationToken cancellationToken) =>
{
    var user = userStore.GetByUsername(request.Username);
    if (user is null || !passwordHasher.Verify(request.Password, user.PasswordHash))
    {
        return Results.Unauthorized();
    }

    var (accessToken, accessTokenExpires, _) = tokenService.CreateAccessToken(user);
    var (refreshRecord, refreshToken) = await refreshTokenService.CreateAsync(user, null, null, httpContext, cancellationToken);

    return Results.Ok(new TokenResponse(
        accessToken,
        accessTokenExpires,
        refreshToken,
        refreshRecord.ExpiresAtUtc));
});

app.MapPost("/auth/refresh", async (
    [FromBody] RefreshRequest request,
    IUserStore userStore,
    IRefreshTokenStore refreshTokenStore,
    IRefreshTokenService refreshTokenService,
    ITokenService tokenService,
    IOptions<RefreshTokenOptions> refreshOptions,
    HttpContext httpContext,
    CancellationToken cancellationToken) =>
{
    var options = refreshOptions.Value;
    var lookup = await refreshTokenService.TryFindAsync(request.RefreshToken, cancellationToken);
    if (!lookup.Success || lookup.ExistingToken is null)
    {
        return Results.Unauthorized();
    }

    var token = lookup.ExistingToken;
    var now = DateTimeOffset.UtcNow;

    if (token.RevokedAtUtc is not null)
    {
        if (now <= token.RevokedAtUtc.Value.AddSeconds(options.ReuseDetectionWindowSeconds))
        {
            await refreshTokenService.RevokeFamilyAsync(token.FamilyId, "Refresh token reuse detected.", cancellationToken);
        }

        return Results.Unauthorized();
    }

    if (!token.IsActive)
    {
        token.RevokedAtUtc = now;
        token.RevocationReason = "Expired token attempted for refresh.";
        await refreshTokenStore.UpdateAsync(token, cancellationToken);
        return Results.Unauthorized();
    }

    var user = userStore.GetById(token.UserId);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    token.RevokedAtUtc = now;
    token.RevocationReason = "Rotated";
    await refreshTokenStore.UpdateAsync(token, cancellationToken);

    var (nextRecord, nextPlaintext) = await refreshTokenService.CreateAsync(user, token.FamilyId, token.Id, httpContext, cancellationToken);
    token.ReplacedByTokenId = nextRecord.Id;
    await refreshTokenStore.UpdateAsync(token, cancellationToken);

    var (accessToken, accessTokenExpires, _) = tokenService.CreateAccessToken(user);
    return Results.Ok(new TokenResponse(accessToken, accessTokenExpires, nextPlaintext, nextRecord.ExpiresAtUtc));
});

app.MapPost("/auth/revoke", async (
    [FromBody] RevokeRequest request,
    IRefreshTokenService refreshTokenService,
    CancellationToken cancellationToken) =>
{
    var lookup = await refreshTokenService.TryFindAsync(request.RefreshToken, cancellationToken);
    if (!lookup.Success || lookup.ExistingToken is null)
    {
        return Results.NotFound();
    }

    await refreshTokenService.RevokeFamilyAsync(lookup.ExistingToken.FamilyId, "Manually revoked.", cancellationToken);
    return Results.NoContent();
}).RequireAuthorization(Policies.ManageUsers);

app.MapGet("/finance/reports", () => Results.Ok(new { Message = "Finance report data" }))
    .RequireAuthorization(Policies.FinanceRead, Policies.MfaRequired);

app.MapPost("/finance/reports", () => Results.Ok(new { Message = "Finance report updated" }))
    .RequireAuthorization(Policies.FinanceWrite, Policies.MfaRequired);

app.MapGet("/hr/employees", () => Results.Ok(new { Message = "HR employee data" }))
    .RequireAuthorization(Policies.HrRead);

app.MapGet("/admin/users", () => Results.Ok(new { Message = "User management data" }))
    .RequireAuthorization(Policies.RequireAdministrator, Policies.ManageUsers, Policies.MfaRequired);

app.Run();
