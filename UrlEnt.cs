namespace UrlShortener.Model;

public class UrlEnt
{
    public int Id { get; set; }
    public required DateTime CreatedAt { get; set; }
    public required string Original { get; set; }
    public required string Shortened { get; set; }
    public DateTime? ExpiredAt { get; set; }

    public void GiveExpirationTime(int seconds)
    {
        ExpiredAt = CreatedAt.AddSeconds(seconds);
    }
}

public static class UrlEntExtensions
{
    public const int NonUserUrlExpirationDuration = 20; // in s

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
            ExpiredAt = url.ExpiredAt,
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
            ExpiredAt = url.ExpiredAt,
            OriginalUrl = url.Original,
            ShortenedUrl = domain + path + url.Shortened
        };
    }
}