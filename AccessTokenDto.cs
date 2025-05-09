using UrlShortener.Interfaces;

namespace UrlShortener.Model;

public class AccessTokenDto
{
    public required string AccessToken { get; set; }
    public DateTime ExpiredAt { get; set; }
}

public static class AccessTokenDtoExtensions
{
    public static AccessTokenDto ToAccessTokenDto(this IToken token)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new AccessTokenDto()
        {
            AccessToken = token.Token,
            ExpiredAt = token.ExpiredAt.ToLocalTime()
        };
    }
}