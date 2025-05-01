namespace UrlShortener.Model;

public class UrlEnt
{
    public int Id { get; set; }
    public required DateTime CreatedAt { get; set; }
    public required string Original { get; set; }
    public required string Shortened { get; set; }
}

public static class UrlEntExtensions
{
    private static string domain = string.Empty;
    private static string path = string.Empty;

    public static void Init(string domain, string path)
    {
        UrlEntExtensions.domain = domain;
        UrlEntExtensions.path = path;
    }

    public static UrlDto ToDto(this UrlEnt url)
    {
        return new UrlDto()
        {
            Id = url.Id,
            CreatedAt = url.CreatedAt,
            OriginalUrl = url.Original,
            ShortenedUrl = domain + path + url.Shortened
        };
    }

    public static UrlDto ToDto(this UrlEnt url, string domain, string? path)
    {
        return new UrlDto()
        {
            Id = url.Id,
            CreatedAt = url.CreatedAt,
            OriginalUrl = url.Original,
            ShortenedUrl = domain + path + url.Shortened
        };
    }
}