# .NET 10 OAuth 2.0 Enterprise API (JWT + Refresh Token Rotation)

This repository contains a .NET 10 minimal API blueprint implementing OAuth 2.0 resource server best practices for enterprise workloads:

- JWT Bearer access tokens (short-lived, signed, validated for issuer/audience/lifetime/signature)
- Opaque refresh tokens with secure hashing-at-rest
- Refresh token rotation with token family tracking and reuse-detection revocation
- Policy-based authorization with role + claim + MFA requirements

## Project structure

- `src/EnterpriseAuthApi/Program.cs` — authN/authZ configuration + endpoints
- `src/EnterpriseAuthApi/Authorization/Policies.cs` — enterprise authorization policies
- `src/EnterpriseAuthApi/Services/*` — access/refresh token issuance and rotation logic
- `src/EnterpriseAuthApi/Security/*` — password hashing and refresh token hashing
- `src/EnterpriseAuthApi/Data/*` — in-memory stores for users and refresh tokens
- `src/EnterpriseAuthApi/Configuration/*` — strongly typed options

## Security notes

1. Access tokens are intentionally short-lived (`AccessTokenMinutes` default = 10).
2. Refresh tokens are random opaque values and **never stored in plaintext**.
3. Rotation is enforced on each refresh.
4. Token family revocation is triggered on suspicious replay.
5. Sensitive endpoints require MFA claim + granular permission claims.

## Running

> Requires .NET 10 SDK preview

```bash
dotnet restore src/EnterpriseAuthApi/EnterpriseAuthApi.csproj
dotnet run --project src/EnterpriseAuthApi/EnterpriseAuthApi.csproj
```

## Example demo users

- `admin / Admin!ChangeMe1` (Administrator + MFA + broad permissions)
- `analyst / Analyst!ChangeMe1` (read-only finance permission)

## Production hardening checklist

- Move user store and refresh token store to durable database with optimistic concurrency.
- Store signing keys in HSM or secure key vault and rotate regularly with `kid` support.
- Enforce TLS at edge, HSTS, and strong reverse proxy headers.
- Add IP/device fingerprinting and anomaly detection for refresh token usage.
- Add centralized token revocation list and distributed cache for scale-out.
- Integrate with OpenID Connect provider for standards-based interactive login.
