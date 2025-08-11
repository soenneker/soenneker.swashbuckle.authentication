using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using Soenneker.Extensions.Configuration;
using Soenneker.Extensions.Enumerable;
using Soenneker.Extensions.HttpContext;
using Soenneker.Extensions.String;
using Soenneker.Extensions.Task;
using Soenneker.Extensions.ValueTask;
using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Threading.Tasks;

namespace Soenneker.Swashbuckle.Authentication;

/// <summary>
/// A middleware implementing basic authentication and RBAC support for Swashbuckle (Swagger)
/// </summary>
public sealed class SwashbuckleAuthMiddleware
{
    private const StringComparison _ord = StringComparison.Ordinal;
    private const StringComparison _ordIgnore = StringComparison.OrdinalIgnoreCase;
    private const string _basicPrefix = "Basic ";

    private readonly RequestDelegate _next;
    private readonly ILogger<SwashbuckleAuthMiddleware> _logger;

    private PathString _uriPath; // store as PathString to avoid conversions
    private bool _localAuthenticationBypassEnabled;
    private string _username = null!;
    private string _password = null!;

    // access-key -> role
    private Dictionary<string, string>? _accessKeyToRole;

    // role -> access-key (for cookie write) - avoids O(n) reverse lookup
    private Dictionary<string, string>? _roleToAccessKey;

    public SwashbuckleAuthMiddleware(RequestDelegate next, IConfiguration config, ILogger<SwashbuckleAuthMiddleware> logger)
    {
        _next = next;
        _logger = logger;
        SetupConfig(config);
    }

    private void SetupConfig(IConfiguration config)
    {
        _username = config.GetValueStrict<string>("Swagger:Username");
        _password = config.GetValueStrict<string>("Swagger:Password");

        var configuredUri = config.GetValue<string>("Swagger:Uri");
        if (configuredUri.IsNullOrEmpty())
        {
            _logger.LogDebug("A swagger uri was not set explicitly, so choosing default '/swagger'");
            _uriPath = new PathString("/swagger");
        }
        else
        {
            _uriPath = new PathString(configuredUri!);
        }

        var accessKeys = config.GetSection("Swagger:AccessKeys").Get<List<string>>();
        if (accessKeys.Populated())
        {
            _accessKeyToRole = new Dictionary<string, string>(accessKeys.Count, StringComparer.Ordinal);
            _roleToAccessKey = new Dictionary<string, string>(accessKeys.Count, StringComparer.Ordinal);

            foreach (string accessKey in accessKeys)
            {
                // Expect "role:key"
                int idx = accessKey.IndexOf(':');
                if (idx <= 0 || idx == accessKey.Length - 1)
                    throw new Exception("Badly formed Swagger access key. Needs to be in format 'role:accessKey'");

                string role = accessKey.Substring(0, idx);
                string key = accessKey.Substring(idx + 1);

                // store both directions
                _accessKeyToRole[key] = role;
                _roleToAccessKey[role] = key;
            }
        }

        _localAuthenticationBypassEnabled = config.GetValue<bool>("Swagger:LocalAuthenticationBypassEnabled");
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Fast path: if not swagger, delegate immediately
        if (!context.Request.Path.StartsWithSegments(_uriPath))
        {
            await _next(context).NoSync();
            return;
        }

        if (await CheckAccessKeys(context).NoSync()) return;
        if (await CheckLocalBypass(context).NoSync()) return;
        if (await CheckCredentials(context).NoSync()) return;

        SetUnauthorized(context, badAttempt: false);
    }

    private async ValueTask<bool> CheckLocalBypass(HttpContext context)
    {
        if (!_localAuthenticationBypassEnabled || !context.IsLocalRequest())
            return false;

        if (_logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Allowed Swagger access because we're local");

        await _next(context).NoSync();
        return true;
    }

    private async ValueTask<bool> CheckCredentials(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue(HeaderNames.Authorization, out StringValues authValues))
            return false;

        // Use the first value (avoids ToString allocation)
        string? authHeader = authValues.Count > 0 ? authValues[0] : null;
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith(_basicPrefix, _ord))
            return false;

        // Extract base64 payload without allocations where possible
        ReadOnlySpan<char> base64 = authHeader.AsSpan(_basicPrefix.Length).Trim();

        if (base64.IsEmpty)
        {
            SetUnauthorized(context, badAttempt: true);
            return true;
        }

        // Base64 decode with stackalloc to avoid intermediate string allocation
        // Max decoded length = (base64Len * 3) / 4
        int maxLen = (base64.Length * 3) / 4;
        Span<byte> bytes = maxLen <= 1024 ? stackalloc byte[maxLen] : new byte[maxLen];

        if (!Convert.TryFromBase64Chars(base64, bytes, out int written))
        {
            SetUnauthorized(context, badAttempt: true);
            return true;
        }

        string decoded = System.Text.Encoding.UTF8.GetString(bytes.Slice(0, written)); // small, unavoidable

        // Parse "username:password" without Split allocation
        int sep = decoded.IndexOf(':');
        if (sep <= 0 || sep == decoded.Length - 1)
        {
            SetUnauthorized(context, badAttempt: true);
            return true;
        }

        ReadOnlySpan<char> username = decoded.AsSpan(0, sep);
        ReadOnlySpan<char> password = decoded.AsSpan(sep + 1);

        if (username.Equals(_username, _ordIgnore) && password.SequenceEqual(_password.AsSpan()))
        {
            SetIdentity(context, userNameForIdentity: _username, role: "admin");
            await _next(context).NoSync();
            return true;
        }

        return false;
    }

    private async ValueTask<bool> CheckAccessKeys(HttpContext context)
    {
        if (_accessKeyToRole is null)
            return false;

        // Prefer explicit query accesskey, else fallback to cookie
        string? accessKey = null;

        if (context.Request.Query.TryGetValue("accesskey", out StringValues qv) && qv.Count > 0)
            accessKey = qv[0];

        // On landing page without ?accesskey, clear any old cookie
        PathString path = context.Request.Path; // PathString, no ToString alloc
        bool onIndex = path.Equals(_uriPath, StringComparison.Ordinal) || path.Equals(_uriPath.Add("/index.html"), StringComparison.Ordinal);

        if (onIndex && string.IsNullOrEmpty(accessKey))
        {
            context.Response.Cookies.Delete("swagger-access-key");
        }

        if (accessKey is null)
        {
            context.Request.Cookies.TryGetValue("swagger-access-key", out accessKey);
        }

        if (accessKey is not null && _accessKeyToRole.TryGetValue(accessKey, out string? role))
        {
            SetIdentity(context, userNameForIdentity: "accesskey", role: role);
            await _next(context).NoSync();
            return true;
        }

        return false;
    }

    private void SetUnauthorized(HttpContext context, bool badAttempt)
    {
        if (badAttempt && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Unauthorized attempt at Swagger from ip {ip}", context.Connection.RemoteIpAddress);

        // Signal Basic challenge; no need to set Authorization on the response
        context.Response.Headers[HeaderNames.WWWAuthenticate] = "Basic";
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
    }

    private void SetIdentity(HttpContext context, string userNameForIdentity, string role)
    {
        // Keep identity light; don't store the full auth header as name
        var identity = new GenericIdentity(userNameForIdentity);
        context.User = new GenericPrincipal(identity, new[] {role});

        if (role == "admin")
            return;

        if (_roleToAccessKey is null)
            return;

        // Write the role's access key as a cookie for subsequent visits
        if (_roleToAccessKey.TryGetValue(role, out string? keyFromRole))
        {
            // You can add options (HttpOnly/SameSite/Secure) here as needed
            context.Response.Cookies.Append("swagger-access-key", keyFromRole);
        }
    }
}