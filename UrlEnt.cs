namespace UrlShortener.Model;

public class UrlEnt
{
    public int Id { get; set; }
    public required DateTime CreatedAt { get; set; }
    public required string Original { get; set; }
    public required string Shortened { get; set; }
}