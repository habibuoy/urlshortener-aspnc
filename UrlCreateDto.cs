using System.Diagnostics;
using System.Reflection;
using System.Text.Json;

namespace UrlShortener.Model;

public class UrlCreateDto
{
    public string? Url { get; set; }

    // Can use this code if accept the url from request body to handle the binding
    // public static async ValueTask<UrlCreateDto?> BindAsync(HttpContext context, ParameterInfo parameterInfo)
    // {
    //     if (context.Request.ContentLength == 0)
    //     {
    //         return await ValueTask.FromResult<UrlCreateDto?>(null);
    //     }

    //     UrlCreateDto? result = null;

    //     try
    //     {
    //         result = await context.Request.ReadFromJsonAsync<UrlCreateDto?>();
    //     }
    //     catch (JsonException error)
    //     {
    //         Debug.WriteLine($"Error while parsing body: {error}");
    //     }

    //     return await ValueTask.FromResult(result);
    // }
}

public static class UrlCreateDtoExtensions
{
    public static UrlEnt ToUrlEnt(this UrlCreateDto dto, DateTime createAt, string shortened)
    {
        return new UrlEnt()
        {
            CreatedAt = createAt,
            Original = dto.Url!,
            Shortened = shortened,
        };
    }
}