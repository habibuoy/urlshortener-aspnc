using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using UrlShortener.Interfaces;
using UrlShortener.Model;

namespace UrlShortener.Handlers;

public class CustomAuthenticationService : IAuthenticationService
{
    private readonly IAuthenticationService defaultService;

    public CustomAuthenticationService(IAuthenticationService defaultService)
    {
        this.defaultService = defaultService;
    }

    public async Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
    {
        if (scheme == IdentityConstants.BearerScheme)
        {
            var tokenOptions = context.RequestServices.GetRequiredService<IOptionsMonitor<BearerTokenOptions>>()
                .Get(IdentityConstants.BearerScheme);

            var expirationTime = DateTime.UtcNow.Add(tokenOptions.BearerTokenExpiration);
            properties ??= new();

            properties.ExpiresUtc = expirationTime;

            var authenticationTicket = new AuthenticationTicket(principal, properties, scheme);
            var tokenProtector = tokenOptions.BearerTokenProtector;

            var token = tokenProtector.Protect(authenticationTicket);

            var tokenDto = new AccessTokenDto()
            {
                AccessToken = token,
                ExpiredAt = expirationTime.ToLocalTime()
            };

            var tokenStore = context.RequestServices.GetRequiredService<ITokenStorer>();
            await tokenStore.RecordAsync(token);

            await context.Response.WriteAsJsonAsync(tokenDto);
        }
        else
        {
            await defaultService.SignInAsync(context, scheme, principal, properties);
        }
    }

    public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
        => defaultService.AuthenticateAsync(context, scheme);

    public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        => defaultService.ChallengeAsync(context, scheme, properties);

    public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        => defaultService.ForbidAsync(context, scheme, properties);

    public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        => defaultService.SignOutAsync(context, scheme, properties);
}