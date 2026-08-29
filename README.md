[![](https://img.shields.io/nuget/v/Soenneker.Swashbuckle.Authentication.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Swashbuckle.Authentication/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.swashbuckle.authentication/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.swashbuckle.authentication/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/Soenneker.Swashbuckle.Authentication.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Swashbuckle.Authentication/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.swashbuckle.authentication/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.swashbuckle.authentication/actions/workflows/codeql.yml)

# Soenneker.Swashbuckle.Authentication

Represents the swagger authorize extensions.

## Install

```bash
dotnet add package Soenneker.Swashbuckle.Authentication
```

## Quick start

```csharp
using Soenneker.Swashbuckle.Authentication.Registrars;

IApplicationBuilder builder = /* obtain from your application */;
var result = builder.UseSwashbuckleAuth();
```

Adds a middleware implementing basic authentication and RBAC support for Swashbuckle (Swagger).

## What you get

- `SwaggerAuthorizeExtensions` — Represents the swagger authorize extensions.
- `SwashbuckleAuthMiddleware` — A middleware implementing basic authentication and RBAC support for Swashbuckle (Swagger).

## API at a glance

| API | What it does | Result / important behavior |
| --- | --- | --- |
| `SwaggerAuthorizeExtensions.UseSwashbuckleAuth(builder)` | Adds a middleware implementing basic authentication and RBAC support for Swashbuckle (Swagger). | The same builder instance, so additional classes or variants can be chained. |
| `SwashbuckleAuthMiddleware.InvokeAsync(context)` | Invokes async. | A task that completes when the invoke async operation is complete. |
