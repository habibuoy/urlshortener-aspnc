using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using UrlShortener.Data;
using UrlShortener.Model;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
var connectionString = builder.Configuration.GetConnectionString("MainDb");

builder.Services.AddSqlServer<ApplicationDbContext>(connectionString);

UrlEntExtensions.Init("https://localhost:7000", "/s/");

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

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
    dbContext.Urls.Add(result);
    await dbContext.SaveChangesAsync();

    return Results.Ok(result.ToDto());
});

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

    return Results.Redirect(result.Original!, true);
});

app.Run();

public static class UrlShortenerUtils
{
    private const string Characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
    private const int MaximumLength = 6;

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
}
