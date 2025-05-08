namespace UrlShortener.Interfaces;

public interface ITokenStorer
{
    Task<TokenOperationResult> RecordAsync(string token);
    Task<TokenOperationResult> ExpireAsync(string token);
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