using Microsoft.AspNetCore.Builder;

namespace Soenneker.Swashbuckle.Authentication.Registrars;

/// <summary>
/// Represents the swagger authorize extensions.
/// </summary>
public static class SwaggerAuthorizeExtensions
{
    /// <summary>
    /// Adds a middleware implementing basic authentication and RBAC support for Swashbuckle (Swagger)
    /// </summary>
    public static IApplicationBuilder UseSwashbuckleAuth(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<SwashbuckleAuthMiddleware>();
    }
}
