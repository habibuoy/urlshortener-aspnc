namespace UrlShortener.Interfaces;

public interface ITokenStorer
{
    Task<TokenOperationResult> RecordAsync(string token, string userIdentifier, DateTime expiredAt);
    Task<TokenOperationResult> ExpireAsync(string token);
    Task<TokenFetchResult> GetTokenAsync(string userIdentifier);
}

public class TokenOperationResult
{
    public virtual bool IsSucceed { get; init; }
    public string Message { get; init; } = string.Empty;

    public TokenOperationResult(bool succeed, string message = "")
    {
        IsSucceed = succeed;
        Message = message;
    }

    public static TokenOperationResult Succeed()
    {
        return new TokenOperationResult(true);
    }

    public static TokenOperationResult Failed(string message = "")
    {
        return new TokenOperationResult(true, message);
    }
}

public interface IToken
{
    string Token { get; }
    DateTime ExpiredAt { get; }
    string UserIdentifier { get; }
    bool IsExpired { get; }
}

public class TokenFetchResult : TokenOperationResult
{
    public IToken? Token { get; init; }

    public TokenFetchResult(bool succeed, IToken? token, string message = "") 
        : base(succeed, message)
    {
        Token = token;
    }

    public static TokenFetchResult Succeed(IToken token)
    {
        return new TokenFetchResult(true, token);
    }
}