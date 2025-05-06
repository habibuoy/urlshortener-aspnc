namespace UrlShortener.Responses;

public class ResponseObject
{
    public string? Message { get; set; }
    public object? Result { get; set; }

    public static ResponseObject Create(string message, object? result = null)
    {
        var responseObject = new ResponseObject()
        {
            Message = message,
            Result = result
        };

        return responseObject;
    }

    public static ResponseObject Create(object? result = null)
        => Create("", result);

    public static ResponseObject TokenExpired(object? result = null)
        => Create("Your token has expired.", result);

    public static ResponseObject TokenNotValid(object? result = null)
        => Create("Your token is not valid.", result);

    public static ResponseObject NotAuthorized(object? result = null)
        => Create("You are not authorized for this resource.", result);
}