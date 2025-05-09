namespace UrlShortener.Interfaces;

public interface ITokenValidator
{
    Task<TokenValidityResult> ValidateAsync(string token);
}

public class TokenValidityResult : TokenOperationResult
{
    public ValidityStatus ValidityStatus { get; init; }

    public TokenValidityResult(bool succeed, ValidityStatus validityStatus)
        : base(succeed)
    {
        ValidityStatus = validityStatus;
    }

    public static TokenValidityResult SucceedWithStatus(ValidityStatus validityStatus)
    {
        return new TokenValidityResult(true, validityStatus);
    }
}

public enum ValidityStatus
{
    NotValid,
    Valid,
    Expired
}