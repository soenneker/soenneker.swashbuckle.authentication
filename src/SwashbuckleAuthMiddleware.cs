using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using Soenneker.Extensions.Dictionary;
using Soenneker.Extensions.Enumerable;
using Soenneker.Extensions.HttpContext;
using Soenneker.Extensions.String;

namespace Soenneker.Swashbuckle.Authentication;

/// <summary>
/// A middleware implementing basic authentication and RBAC support for Swashbuckle (Swagger)
/// </summary>
/// <remarks>
/// The following configuration entries are required:
/// Swagger:LocalAuthenticationBypassEnabled <para/>
/// Swagger:Username (Admin)<para/>
/// Swagger:Password (Admin)<para/>
///
/// Optional:
/// Swagger:Uri <para/>
/// Swagger:AccessKeys <para/>
/// "role:key"
/// </remarks>
public class SwashbuckleAuthMiddleware
{
    private readonly RequestDelegate _next;

    private readonly ILogger<SwashbuckleAuthMiddleware> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    private string? _uri;
    private bool _localAuthenticationBypassEnabled;
    private string? _username;
    private string? _password;

    private Dictionary<string, string>? _accessKeyRoles;

    public SwashbuckleAuthMiddleware(RequestDelegate next, IConfiguration config, IHttpContextAccessor httpContextAccessor, ILogger<SwashbuckleAuthMiddleware> logger)
    {
        _next = next;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;

        SetupConfig(config);
    }

    private void SetupConfig(IConfiguration config)
    {
        _username = config.GetValue<string>("Swagger:Username");

        if (_username.IsNullOrEmpty())
            throw new Exception("Swagger:Username must be set in configuration");

        _password = config.GetValue<string>("Swagger:Password");

        if (_password.IsNullOrEmpty())
            throw new Exception("Swagger:Password must be set in configuration");

        var configuredUri = config.GetValue<string>("Swagger:Uri");

        if (configuredUri.IsNullOrEmpty())
        {
            _logger.LogDebug("A swagger uri was not set explicitly, so choosing default '/swagger'");
            _uri = "/swagger";
        }
        else
        {
            _uri = configuredUri;
        }

        var accessKeys = config.GetValue<List<string>>("Swagger:AccessKeys");

        if (accessKeys.Populated())
        {
            _accessKeyRoles = new Dictionary<string, string>();

            foreach (string accessKey in accessKeys)
            {
                // Expects e.g. "user:key"
                string[] split = accessKey.Split(':');

                if (split.Length != 2) // TODO: More validation here
                    throw new Exception("Badly formed Swagger access key. Needs to be in format 'user:accessKey'");

                // stores via key because that's the lookup
                _accessKeyRoles.Add(split[1], split[0]);
            }
        }

        var localBypassEnabled = config.GetValue<bool>("Swagger:LocalAuthenticationBypassEnabled");

        _localAuthenticationBypassEnabled = localBypassEnabled;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Path.StartsWithSegments(_uri))
        {
            // Any other request
            await _next.Invoke(context);
            return;
        }

        if (await CheckAccessKeys(context))
            return;

        if (await CheckLocalBypass(context))
            return;

        if (await CheckCredentials(context))
            return;

        SetUnauthorized(context, false);
    }

    private async ValueTask<bool> CheckLocalBypass(HttpContext context)
    {
        if (!_localAuthenticationBypassEnabled)
            return false;

        if (!context.IsLocalRequest())
            return false;

        _logger.LogDebug("Allowed Swagger access because we're local");
        await _next.Invoke(context);
        return true;
    }

    private async ValueTask<bool> CheckCredentials(HttpContext context)
    {
        context.Request.Headers.TryGetValue(HeaderNames.Authorization, out StringValues authHeaderValue);

        string authHeader = authHeaderValue.ToString();

        if (!authHeader.IsNullOrEmpty() && authHeader.StartsWith("Basic "))
        {
            string encodedUsernamePassword = authHeader.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries)[1].Trim();

            if (encodedUsernamePassword.IsNullOrEmpty())
            {
                SetUnauthorized(context, true);
                return true;
            }

            string decodedUsernamePassword = encodedUsernamePassword.ToStringFromEncoded64();

            string[] credentialArray = decodedUsernamePassword.Split(':', 2);

            if (credentialArray.Length != 2)
            {
                SetUnauthorized(context, true);
                return true;
            }

            string username = credentialArray[0];
            string password = credentialArray[1];

            if (username.Equals(_username, StringComparison.OrdinalIgnoreCase) && password == _password)
            {
                SetIdentity(context, authHeader, "admin");

                await _next.Invoke(context);
                return true;
            }
        }

        return false;
    }

    private async ValueTask<bool> CheckAccessKeys(HttpContext context)
    {
        string? accessKey = null;

        if (context.Request.Query.TryGetValue("accesskey", out StringValues stringValueAccessKey))
            accessKey = stringValueAccessKey.ToString();

        string? cookieAccessKey = null;

        var path = context.Request.Path.ToString();

        if (path == _uri || path == $"{_uri}/index.html")
        {
            if (accessKey.IsNullOrEmpty())
                _httpContextAccessor.HttpContext!.Response.Cookies.Delete("swagger-access-key");
            else
                _httpContextAccessor.HttpContext!.Request.Cookies.TryGetValue("swagger-access-key", out cookieAccessKey);
        }
        else
        {
            _httpContextAccessor.HttpContext!.Request.Cookies.TryGetValue("swagger-access-key", out cookieAccessKey);
        }

        if (_accessKeyRoles.Populated())
        {
            string? role;

            if (accessKey != null)
            {
                if (_accessKeyRoles.TryGetValue(accessKey, out role))
                {
                    SetIdentity(context, "", role);

                    await _next.Invoke(context);
                    return true;
                }
            }
            else if (cookieAccessKey != null)
            {
                if (_accessKeyRoles.TryGetValue(cookieAccessKey, out role))
                {
                    SetIdentity(context, "", role);

                    await _next.Invoke(context);
                    return true;
                }
            }
        }

        return false;
    }

    public void SetUnauthorized(HttpContext context, bool badAttempt)
    {
        if (badAttempt)
            _logger.LogDebug("Unauthorized attempt at Swagger from ip {ip}", context.Connection.RemoteIpAddress);

        // Return authentication type (causes browser to show login dialog)
        context.Response.Headers[HeaderNames.WWWAuthenticate] = "Basic";
        context.Response.Headers[HeaderNames.Authorization] = new StringValues("");

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
    }

    private void SetIdentity(HttpContext context, string authHeader, string role)
    {
        var identity = new GenericIdentity(authHeader);
        var newPrincipal = new GenericPrincipal(identity, new[] {role});
        context.User = newPrincipal;

        if (role == "admin")
            return;

        if (_accessKeyRoles == null)
            return;

        if (_accessKeyRoles.TryGetKeyFromValue(role, out string? keyFromRole))
        {
            _httpContextAccessor.HttpContext!.Response.Cookies.Append("swagger-access-key", keyFromRole);
        }
    }
}