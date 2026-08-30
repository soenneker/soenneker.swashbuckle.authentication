[![](https://img.shields.io/nuget/v/Soenneker.Swashbuckle.Authentication.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Swashbuckle.Authentication/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.swashbuckle.authentication/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.swashbuckle.authentication/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/Soenneker.Swashbuckle.Authentication.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Swashbuckle.Authentication/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.swashbuckle.authentication/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.swashbuckle.authentication/actions/workflows/codeql.yml)

# Soenneker.Swashbuckle.Authentication

Protects a Swagger path with HTTP Basic credentials, optional role-bearing access keys, or an explicit local-request bypass.

## Installation

```bash
dotnet add package Soenneker.Swashbuckle.Authentication
```

## Configuration

```json
{
  "Swagger": {
    "Uri": "/swagger",
    "Username": "docs-admin",
    "Password": "replace-with-a-secret",
    "LocalAuthenticationBypassEnabled": false,
    "AccessKeys": [
      "support:replace-with-a-random-key",
      "developer:replace-with-another-random-key"
    ]
  }
}
```

`Username` and `Password` are required. `Uri` defaults to `/swagger`. Each optional access-key entry uses `role:key`; a successful key creates an authenticated principal named `accesskey` with that role. Basic credentials create an `admin` principal.

Keep credentials and access keys in a secret provider or environment variables rather than a committed settings file.

## Middleware order

Register authentication before the Swagger middleware so requests cannot reach the UI or JSON document first:

```csharp
using Soenneker.Swashbuckle.Authentication.Registrars;

app.UseSwashbuckleAuth();
app.UseSwagger();
app.UseSwaggerUI();
```

Requests outside the configured Swagger path pass through unchanged. Unauthorized requests under that path receive `401` with a Basic authentication challenge.

## Access-key links

An access key can be supplied as `?accesskey=...`. A valid key is persisted in an HTTP-only, same-site session cookie restricted to the Swagger path; the cookie is marked secure when the request uses HTTPS.

Query strings commonly appear in browser history, proxy logs, monitoring tools, and copied URLs. Use random, revocable keys, send access-key links only over HTTPS, and remove the key from the address bar after the first authenticated request. Opening the Swagger landing page without an access-key query clears the existing access-key cookie.

## Local bypass

Leave `LocalAuthenticationBypassEnabled` disabled unless the deployment's connection-address handling is fully trusted. The bypass relies on `HttpContext.Connection` addresses; forwarded-header middleware, proxies, or test middleware that rewrites those addresses can affect what counts as local.

This middleware protects Swagger endpoints but is not a replacement for application-wide authentication, authorization, TLS, rate limiting, or secret rotation.
