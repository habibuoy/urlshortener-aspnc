namespace UrlShortener.Model;

public class AccessTokenDto
{
    public required string AccessToken { get; set; }
    public DateTime ExpiredAt { get; set; }
}