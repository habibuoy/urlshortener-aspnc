namespace UrlShortener.Model;

public class UrlDto
{
    public int Id { get; set; }
    public DateTime? CreatedAt { get; set; }
    public string? OriginalUrl { get; set; }
    public string? ShortenedUrl { get; set; }
    public DateTime? ExpiredAt { get; set; }
}