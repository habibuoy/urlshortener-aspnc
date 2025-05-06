using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using UrlShortener.Data;
using UrlShortener.Model;
using Microsoft.AspNetCore.Authorization;
using System.Text.Json.Nodes;

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

builder.Services.AddIdentityCore<IdentityUser>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddApiEndpoints();

UrlEntExtensions.Init("https://localhost:7000", "/s/");

var app = builder.Build();
app.MapIdentityApi<IdentityUser>();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// put this middleware before the authentication and authorization middleware
// for writing the response body with 401 response code
// also for capturing the token generated after the authentication process
app.Use(async (context, next) =>
{
    var endpoint = context.GetEndpoint();

    bool isLoginPath = context.Request.Path == "/login";

    // cache the original body stream as it was a forward-only body and can only be read
    // once the response is written
    var originalBodyStream = context.Response.Body;
    MemoryStream memoryStream = null;
    
    // replace the original response body stream with a MemoryStream
    if (isLoginPath)
    {
        memoryStream = new MemoryStream();
        context.Response.Body = memoryStream;
    }

    // check if the token has been manually expired by hitting /logout endpoint
    // then do not proceed the request pipeline
    // and return 401 response code
    if (endpoint != null
        && endpoint.Metadata.Any(m => m.GetType() == typeof(AuthorizeAttribute)
        && !isLoginPath))
    {
        var authorization = context.Request.Headers.Authorization.ToString();
        if (authorization.Contains("Bearer"))
        {
            var token = authorization.Replace("Bearer", "").Trim();
            var tokenManager = context.RequestServices.GetRequiredService<BearerTokenManager>();
            if (!tokenManager.IsValid(token))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync("Your token is expired");
                return;
            }
        }
    }

    // proceed with the rest of the pipeline
    await next();

    // if the request is to login path
    // we store the the generated token into our own token manager so that
    // we can manually expire it instead of waiting for the expiration time
    if (isLoginPath
        && context.Response.StatusCode == StatusCodes.Status200OK)
    {
        // move the stream position to the beginning
        // and read the stream and return as json string
        memoryStream!.Seek(0, SeekOrigin.Begin);
        var responseBody = await new StreamReader(memoryStream).ReadToEndAsync();

        try
        {
            var jsonNode = JsonNode.Parse(responseBody);
            if (jsonNode != null
                && jsonNode["accessToken"] is JsonNode accToken)
            {
                // get the token value in the json body using
                // accessToken key from ASP.NET Core AccessTokenResponse object
                var accessToken = accToken.GetValue<string>();
                var tokenManager = context.RequestServices.GetRequiredService<BearerTokenManager>();

                // then store it into our token manager
                var success = tokenManager.Add(accessToken);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error while deserializing the access token: {ex}");
        }

        // move the stream position bac to the beginning
        // and copy its value to the original response body stream
        memoryStream.Seek(0, SeekOrigin.Begin);
        await memoryStream.CopyToAsync(originalBodyStream);

        // then reassign the original response body stream;
        context.Response.Body = originalBodyStream;
    }

    // don't forget to release the resource
    memoryStream?.Dispose();

    // if the response code is 401 and the body is empty
    // we write a custom body
    if (context.Response.StatusCode == StatusCodes.Status401Unauthorized
            && !context.Response.HasStarted)
    {
        await context.Response.WriteAsJsonAsync("Please provide valid token");
    }
});

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/all", static async (ApplicationDbContext dbContext) =>
{
    return await dbContext.Urls.Select(url => url.ToDto()).ToListAsync();
});

app.MapPost("/create", static async ([AsParameters] UrlCreateDto url, ApplicationDbContext dbContext) =>
{
    if (url == null
        || string.IsNullOrEmpty(url.Url)
        || !Uri.TryCreate(url.Url, UriKind.Absolute, out var uri))
    {
        return Results.BadRequest("Please provide a valid URL that you want to shorten.");
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

    return Results.Ok(result.ToDto());
});

app.MapPost("/create/custom", static async ([AsParameters] UrlCustomCreateDto url, HttpContext context, ApplicationDbContext dbContext) =>
{
    Debug.WriteLine($"Authorization: {context.Request.Headers.Authorization}");
    if (url == null
        || string.IsNullOrEmpty(url.Url)
        || !Uri.TryCreate(url.Url, UriKind.Absolute, out var uri))
    {
        return Results.BadRequest("Please provide a valid URL that you want to shorten.");
    }

    if (string.IsNullOrEmpty(url.CustomPath)
        || !UrlShortenerUtils.ValidateCustomPath(url.CustomPath))
    {
        return Results.BadRequest("Please provide a valid custom path for you shortened URL. Maximum 20 characters and only alpabhet and numbers");
    }

    if (await dbContext.Urls.FirstOrDefaultAsync(u => u.Shortened == url.CustomPath) is not null)
    {
        return Results.Conflict($"Custom path: {url.CustomPath} already exists, please choose another");
    }

    var result = url.ToUrlEnt(DateTime.Now, url.CustomPath);
    dbContext.Urls.Add(result);
    await dbContext.SaveChangesAsync();

    return Results.Ok(result.ToDto());
})
.RequireAuthorization();

app.MapGet("/id/{id:int}", static async (int? id, ApplicationDbContext dbContext) =>
{
    if (id == null
        || await dbContext.Urls.FindAsync(id) is not UrlEnt existing)
    {
        return Results.NotFound("Url not found. Please provide valid id.");
    }

    return Results.Ok(existing.ToDto());
});

app.MapDelete("/id/{id:int}", static async (int? id, ApplicationDbContext dbContext) =>
{
    if (id == null
        || await dbContext.Urls.FindAsync(id) is not UrlEnt existing)
    {
        return Results.NotFound("Url not found. Please provide valid id.");
    }

    dbContext.Remove(existing);
    await dbContext.SaveChangesAsync();

    return Results.Ok($"Url with id {id} was deleted successfully.");
});

app.MapGet("/s/{url}", static async (string? url, ApplicationDbContext dbContext) =>
{
    if (string.IsNullOrEmpty(url)
        || await dbContext.Urls.FirstOrDefaultAsync(u => u.Shortened == url) is not UrlEnt result)
    {
        return Results.NotFound("Please provide valid shortened url.");
    }

    if (result.ExpiredAt != null
        && DateTime.Now > result.ExpiredAt)
    {
        return Results.Ok("This url has expired and cannot be used again.");
    }

    return Results.Redirect(result.Original!, true);
});

app.MapPost("/logout", static async (HttpContext context) =>
{
    var authorization = context.Request.Headers.Authorization.ToString();
    var token = authorization.Replace("Bearer", "").Trim();

    var tokenManager = context.RequestServices.GetRequiredService<BearerTokenManager>();
    tokenManager.Expire(token);
}).RequireAuthorization();

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

public class BearerTokenManager
{
    public readonly List<BearerToken> bearerTokens = new();

    public bool Add(string token)
    {
        if (bearerTokens.Find(t => t.Token == token) is not null)
        {
            return false;
        }

        bearerTokens.Add(new BearerToken()
        {
            Token = token
        });

        return true;
    }

    public bool Expire(string token)
    {
        if (bearerTokens.Find(t => t.Token == token) is BearerToken bearerToken)
        {
            bearerToken.IsExpired = true;
            return true;
        }

        return false;
    }

    public bool IsValid(string token)
    {
        if (bearerTokens.FirstOrDefault(t => t.Token == token) is BearerToken bearerToken)
        {
            return !bearerToken.IsExpired;
        }

        return false;
    }

    public class BearerToken
    {
        public required string Token { get; set; }
        public bool IsExpired { get; set; }

        public override string ToString()
        {
            return Token;
        }
    }
}
