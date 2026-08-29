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
    /// <param name="builder">Builder to configure.</param>
    /// <returns>The same builder instance, so additional classes or variants can be chained.</returns>
    public static IApplicationBuilder UseSwashbuckleAuth(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<SwashbuckleAuthMiddleware>();
    }
}
