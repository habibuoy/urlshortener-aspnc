namespace UrlShortener.Model;

public class UrlCustomCreateDto : UrlCreateDto
{
    public required string CustomPath { get; set; }
}