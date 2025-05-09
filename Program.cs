using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using UrlShortener.Data;
using UrlShortener.Model;
using UrlShortener.BackgroundServices;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.BearerToken;
using UrlShortener.Responses;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;
using UrlShortener.Handlers;
using Microsoft.AspNetCore.Authorization;
using UrlShortener.Interfaces;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddSingleton<BearerTokenManager>();
var connectionString = builder.Configuration.GetConnectionString("MainDb");

builder.Services.AddSqlServer<ApplicationDbContext>(connectionString);
builder.Services.AddAuthentication()
    .AddBearerToken(IdentityConstants.BearerScheme, options => options.BearerTokenExpiration = TimeSpan.FromSeconds(60));
builder.Services.AddAuthorization();

// make sure to add SignInManager
builder.Services.AddIdentityCore<IdentityUser>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager<SignInManager<IdentityUser>>();

builder.Services.AddScoped<IAuthenticationService, CustomAuthenticationService>(
    (provider) => new CustomAuthenticationService(ActivatorUtilities.CreateInstance<AuthenticationService>(provider))
);

var tokenManager = new BearerTokenManager();
builder.Services.AddSingleton<ITokenStorer>(tokenManager);
builder.Services.AddSingleton<ITokenValidator>(tokenManager);

builder.Services.AddHostedService<ExpiredUrlRemoverHostedService>();
UrlEntExtensions.Init("https://localhost:7000", "/s/");

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// put this middleware before the authentication and authorization middleware
// for writing the response body with 401 response code
app.Use(async (context, next) =>
{
    try
    {
        var endpoint = context.GetEndpoint();
        // check if the token has been manually expired by hitting /logout endpoint
        // then do not proceed the request pipeline
        // and return 401 response code
        if (endpoint != null
            && endpoint.Metadata.Any(m => m.GetType() == typeof(AuthorizeAttribute)))
        {
            var authorization = context.Request.Headers.Authorization.ToString();
            if (authorization.StartsWith("Bearer"))
            {
                var token = authorization.Replace("Bearer", "").Trim();
                var tokenValidator = context.RequestServices.GetRequiredService<ITokenValidator>();
                var validityResult = await tokenValidator.ValidateAsync(token);

                if (!validityResult.IsSucceed
                    || validityResult.ValidityStatus != ValidityStatus.Valid)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsJsonAsync(validityResult.ValidityStatus.ToResponseObject());
                    return;
                }
            }
        }

        await next(context);

        // if the response code is 401 and the body is empty
        // we write a custom body
        if (context.Response.StatusCode == StatusCodes.Status401Unauthorized
                && !context.Response.HasStarted)
        {
            await context.Response.WriteAsJsonAsync(ResponseObject.TokenNotValid());
        }
    }
    catch (Exception ex)
    {
        var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();

        if (ex is BadHttpRequestException badHttpRequestException)
        {
            logger.LogError("There was an error parsing request data {reqId}: {ex}", context.TraceIdentifier, ex);

            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsJsonAsync(ResponseObject.Create("Please provide a valid request data"));
        }
        else
        {
            logger.LogError("There was an processing request {reqId}: {ex}", context.TraceIdentifier, ex);

            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await context.Response.WriteAsJsonAsync(ResponseObject.Create("There was an error processing your request on our server"));
        }
    }
});

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/register", static async ([FromBody] RegisterRequest? registerRequest,
    [FromServices] IServiceProvider sp) =>
{
    if (registerRequest == null)
    {
        return Results.BadRequest(ResponseObject.Create("Please provide a valid request body"));
    }

    var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();

    if (!userManager.SupportsUserEmail)
    {
        throw new NotSupportedException($"/register endpoint needs user manager that supports email!");
    }

    var email = registerRequest.Email;
    if (string.IsNullOrEmpty(email)
        || !IdentityHelper.IsEmailValid(email))
    {
        return Results.BadRequest(ResponseObject.Create($"Please provide a valid email address"));
    }

    var user = new IdentityUser();
    await userManager.SetUserNameAsync(user, email);
    await userManager.SetEmailAsync(user, email);

    var userResult = await userManager.CreateAsync(user, registerRequest.Password);

    if (!userResult.Succeeded)
    {
        var errorPairs = userResult.Errors.Aggregate(new Dictionary<string, string[]>(),
            (acc, next) =>
        {
            if (!acc.ContainsKey(next.Code))
            {
                acc[next.Code] = [next.Description];
            }

            return acc;
        });

        var problemDetails = new HttpValidationProblemDetails(errorPairs);

        return Results.BadRequest(ResponseObject.Create("Please provide a valid password", problemDetails));
    }

    return Results.Ok(ResponseObject.Create($"User {registerRequest.Email} has been registered succesfully"));
});

app.MapPost("/login", static async ([FromBody] LoginRequest? loginRequest,
    HttpContext context) =>
{
    if (loginRequest == null)
    {
        return Results.BadRequest(ResponseObject.Create("Please provide a valid request body"));
    }

    var signInManager = context.RequestServices.GetRequiredService<SignInManager<IdentityUser>>();

    signInManager.AuthenticationScheme = IdentityConstants.BearerScheme;

    var user = await signInManager.UserManager.FindByNameAsync(loginRequest.Email);
    if (user == null
        || !(await signInManager.CheckPasswordSignInAsync(user, loginRequest.Password, IdentityHelper.LockOutOnFailed)).Succeeded)
    {
        return Results.BadRequest(ResponseObject.Create("Invalid login credential"));
    }

    var tokenStorer = context.RequestServices.GetRequiredService<ITokenStorer>();
    var existing = await tokenStorer.GetTokenAsync(user.Id);
    if (existing.IsSucceed
        && existing.Token is IToken token
        && !token.IsExpired)
    {
        return Results.Ok(ResponseObject.Create(existing.Token.ToAccessTokenDto()));
    }

    await signInManager.SignInWithClaimsAsync(user, false, []);

    // token response is already written by authentication service. Return Empty.
    return Results.Empty;
});

app.MapGet("/all", static async (ApplicationDbContext dbContext, HttpContext httpContext) =>
{
    var userId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
    var result = await dbContext.Urls
        .Where(u => u.CreatorUserId == userId)
        .Select(url => url.ToDto()).ToListAsync();

    return Results.Ok(ResponseObject.Create(result));
})
.RequireAuthorization();

app.MapPost("/create", static async ([AsParameters] UrlCreateDto url, ApplicationDbContext dbContext) =>
{
    if (url == null
        || string.IsNullOrEmpty(url.Url)
        || !Uri.TryCreate(url.Url, UriKind.Absolute, out var uri))
    {
        return Results.BadRequest(ResponseObject.Create("Please provide a valid URL that you want to shorten."));
    }

    string shortened = "";
    while (string.IsNullOrEmpty(shortened)
        || dbContext.Urls.Any(url => url.Shortened == shortened))
    {
        shortened = UrlShortenerUtils.Generate();
    }

    var result = url.ToUrlEnt(DateTime.Now, shortened);
    result.GiveExpirationTime(UrlEntExtensions.NonUserUrlExpirationDuration);
    dbContext.Urls.Add(result);
    await dbContext.SaveChangesAsync();

    return Results.Ok(ResponseObject.Create(result.ToDto()));
});

app.MapPost("/create/custom", static async ([AsParameters] UrlCustomCreateDto url, HttpContext context, ApplicationDbContext dbContext) =>
{
    if (url == null
        || string.IsNullOrEmpty(url.Url)
        || !Uri.TryCreate(url.Url, UriKind.Absolute, out var uri))
    {
        return Results.BadRequest(ResponseObject.Create("Please provide a valid URL that you want to shorten."));
    }

    if (string.IsNullOrEmpty(url.CustomPath)
        || !UrlShortenerUtils.ValidateCustomPath(url.CustomPath))
    {
        return Results.BadRequest(ResponseObject.Create(
            "Please provide a valid custom path for you shortened URL. Maximum 20 characters and only alphabet and numbers"));
    }

    if (await dbContext.Urls.FirstOrDefaultAsync(u => u.Shortened == url.CustomPath) is not null)
    {
        return Results.Conflict(ResponseObject.Create($"Custom path: {url.CustomPath} already exists, please choose another"));
    }

    var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
    var result = url.ToUrlEnt(DateTime.Now, url.CustomPath);
    result.CreatorUserId = userId;
    dbContext.Urls.Add(result);
    await dbContext.SaveChangesAsync();

    return Results.Ok(ResponseObject.Create(result.ToDto()));
})
.RequireAuthorization();

app.MapGet("/id/{id:int}", static async (int? id, ApplicationDbContext dbContext, HttpContext context) =>
{
    if (id == null)
    {
        return Results.NotFound(ResponseObject.Create("Please provide valid id.", null));
    }

    if (await dbContext.Urls.FindAsync(id) is not UrlEnt existing)
    {
        return Results.NotFound(ResponseObject.Create("Url not found. Please provide valid id.", null));
    }

    string authorizationHeader = context.Request.Headers.Authorization.ToString();
    bool hasBearerToken = authorizationHeader.Contains("Bearer");

    bool isAuthorized = true;

    if (existing.CreatorUserId != null)
    {
        if (!hasBearerToken)
        {
            isAuthorized = false;
        }
        else
        {
            var token = authorizationHeader.Replace("Bearer", "").Trim();
            var tokenValidator = context.RequestServices.GetRequiredService<ITokenValidator>();
            var validityResult = await tokenValidator.ValidateAsync(token);

            if (!validityResult.IsSucceed
                || validityResult.ValidityStatus != ValidityStatus.Valid)
            {
                return Results.Json(validityResult.ValidityStatus.ToResponseObject(),
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            var tokenOptions = context.RequestServices.GetRequiredService<IOptionsMonitor<BearerTokenOptions>>();
            var tokenProtector = tokenOptions.Get(IdentityConstants.BearerScheme).BearerTokenProtector;

            var tokenData = tokenProtector.Unprotect(token);
            var userId = tokenData!.Principal.FindFirstValue(ClaimTypes.NameIdentifier);

            isAuthorized = userId == existing.CreatorUserId;
        }
    }

    if (!isAuthorized)
    {
        return Results.Json(ResponseObject.NotAuthorized(),
            statusCode: StatusCodes.Status401Unauthorized);
    }

    return Results.Ok(ResponseObject.Create(existing.ToDto()));
});

app.MapDelete("/id/{id:int}", static async (int? id, ApplicationDbContext dbContext, ClaimsPrincipal user) =>
{
    if (id == null
        || await dbContext.Urls.FindAsync(id) is not UrlEnt existing)
    {
        return Results.NotFound(ResponseObject.Create("Url not found. Please provide valid id."));
    }

    if (existing.CreatorUserId == null
        || existing.CreatorUserId != user.FindFirstValue(ClaimTypes.NameIdentifier))
    {
        return Results.Json(ResponseObject.NotAuthorized(), statusCode: StatusCodes.Status401Unauthorized);
    }

    dbContext.Remove(existing);
    await dbContext.SaveChangesAsync();

    return Results.Ok(ResponseObject.Create($"Url with id {id} was deleted successfully."));
})
.RequireAuthorization();

app.MapGet("/s/{url}", static async (string? url, ApplicationDbContext dbContext) =>
{
    if (string.IsNullOrEmpty(url)
        || await dbContext.Urls.FirstOrDefaultAsync(u => u.Shortened == url) is not UrlEnt result)
    {
        return Results.NotFound(ResponseObject.Create("Please provide valid shortened url."));
    }

    if (result.ExpiredAt != null
        && DateTime.Now > result.ExpiredAt)
    {
        return Results.Json(ResponseObject.Create("This url has expired and cannot be used again."),
            statusCode: StatusCodes.Status204NoContent);
    }

    return Results.Redirect(result.Original!, true);
});

app.MapPost("/logout", static async (HttpContext context) =>
{
    var authorization = context.Request.Headers.Authorization.ToString();
    var token = authorization.Replace("Bearer", "").Trim();

    var tokenStore = context.RequestServices.GetRequiredService<ITokenStorer>();
    await tokenStore.ExpireAsync(token);

    return Results.Ok(ResponseObject.Create("Logged out succesfully. Token has been expired"));
})
.RequireAuthorization();

app.Run();

public static partial class UrlShortenerUtils
{
    private const string Characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
    private const int MaximumLength = 6;
    private const int MaximumCustomPathLength = 20;
    private const string CustomPathRegexPattern = "^[a-zA-Z0-9]*$";

    [GeneratedRegex(CustomPathRegexPattern)]
    private static partial Regex CustomPathRegex();

    public static string Generate(int maximumLength = MaximumLength)
    {
        var byteArray = new byte[maximumLength];

        using var randomNumberGenerator = RandomNumberGenerator.Create();

        randomNumberGenerator.GetBytes(byteArray, 0, maximumLength);
        string numbers = "";
        for (int i = 0; i < maximumLength; i++)
        {
            int index = byteArray[i] % Characters.Length;
            numbers += Characters[index];
        }
        return numbers;
    }

    public static bool ValidateCustomPath(string customPath)
    {
        if (customPath.Length > MaximumCustomPathLength) return false;
        return CustomPathRegex().IsMatch(customPath);
    }
}

public static class IdentityHelper
{
    private static EmailAddressAttribute emailAddressAttribute = new();

    public const bool LockOutOnFailed = false;

    public static bool IsEmailValid(string email)
    {
        return emailAddressAttribute.IsValid(email);
    }
}

public class BearerTokenManager : ITokenStorer, ITokenValidator
{
    private readonly List<BearerToken> bearerTokens = new();

    public Task<TokenOperationResult> RecordAsync(string token, string userIdentifier, DateTime expiredAt)
    {
        if (bearerTokens.Find(t => t.Token == token) is not null)
        {
            return Task.FromResult(TokenOperationResult.Failed("Token has already been stored"));
        }

        bearerTokens.Add(new BearerToken()
        {
            Token = token,
            UserIdentifier = userIdentifier,
            ExpiredAt = expiredAt
        });

        return Task.FromResult(TokenOperationResult.Succeed());
    }

    public Task<TokenOperationResult> ExpireAsync(string token)
    {
        if (bearerTokens.Find(t => t.Token == token) is BearerToken bearerToken)
        {
            bearerToken.IsExpired = true;
            return Task.FromResult(TokenOperationResult.Succeed());
        }

        return Task.FromResult(TokenOperationResult.Failed("Token not found"));
    }

    public Task<TokenFetchResult> GetTokenAsync(string userIdentifier)
    {
        if (bearerTokens.Find(t => t.UserIdentifier == userIdentifier
            && t.ExpiredAt > DateTime.UtcNow
            && !t.IsExpired) is BearerToken bearerToken)
        {
            return Task.FromResult(TokenFetchResult.Succeed(bearerToken));
        }

        return Task.FromResult(new TokenFetchResult(false, null, "Token not found"));
    }

    public Task<TokenValidityResult> ValidateAsync(string token)
    {
        if (bearerTokens.FirstOrDefault(t => t.Token == token) is BearerToken bearerToken)
        {
            if (DateTime.UtcNow >= bearerToken.ExpiredAt)
            {
                bearerToken.IsExpired = true;
            }
            
            return Task.FromResult(
                    TokenValidityResult.SucceedWithStatus(
                        bearerToken.IsExpired ? ValidityStatus.Expired : ValidityStatus.Valid));
        }

        return Task.FromResult(TokenValidityResult.SucceedWithStatus(ValidityStatus.NotValid));
    }

    public class BearerToken : IToken
    {
        public required string Token { get; init; }
        public required string UserIdentifier { get; init; }
        public DateTime ExpiredAt { get; init; }
        public bool IsExpired { get; set; }

        public override string ToString()
        {
            return Token;
        }
    }
}

public static class ValidityStatusExtensions
{
    public static ResponseObject ToResponseObject(this ValidityStatus validity, object? result = null)
    {
        string message = "";

        switch (validity)
        {
            case ValidityStatus.Expired:
                return ResponseObject.TokenExpired(result);
            case ValidityStatus.NotValid:
                message = "Your token is not valid";
                break;
        }

        return ResponseObject.Create(message, result);
    }
}