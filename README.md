# urlshortener-aspnc
A simple URL Shortener API using ASP.NET Core Minimal API

### Packages used:
- Microsoft EF Core
- Microsoft EF Core SQL Server
- Microsoft ASP.NET Core Identity

### Database
This project uses SQL Server as its database and assumes you have a running SQL Server database named **UrlsData**.
You can run the `dotnet ef database update after you clone this repository to run the necessary migrations.

### Endpoints
| endpoint            | query param                       | request body                         | authorization header | response body                                 | Example                                                                           |
|---------------------|-----------------------------------|--------------------------------------|----------------------|-----------------------------------------------|-----------------------------------------------------------------------------------|
| POST /register      |                 -                 | [RegisterRequest](#register-request) |           -          |                       -                       | https://localhost:7000/register                                                   |
| POST /login         |                 -                 |    [LoginRequest](#login-request)    |           -          | [AccessTokenResponse](#access-token-response) | https://localhost:7000/login                                                      |
| POST /logout        |                 -                 |                   -                  |    Bearer {token}    |                       -                       | https://localhost:7000/logout                                                     |
| GET /all            |                 -                 |                   -                  |           -          |         [UrlResponses](#url-responses)        | https://localhost:7000/all                                                        |
| POST /create        |            url (string)           |                   -                  |                      |          [UrlResponse](#url-response)         | https://localhost:7000/create?url=https://www.google.com                          |
| POST /create/custom | url (string), customPath (string) |                   -                  |    Bearer {token}    |          [UrlResponse](#url-response)         | https://localhost:7000/create/custom?url=https://www.google.com&customPath=google |
| GET /id/{id}        |                 -                 |                   -                  |           -          |          [UrlResponse](#url-response)         | https://localhost:7000/id/1                                                       |
| GET /s/{url}        |                 -                 |                   -                  |           -          |                       -                       | https://localhost:7000/s/google                                                   |

To access endpoints that need authorization, include an access token obtained from the `/login` endpoint as a bearer token in the authorization header. `--header 'Authorization: Bearer {token}'`.  

### JSON Objects
#### Register Request
```
  {
    "email": "email@example.com",
    "password": "Password123@"
  }
```
Email: string (Required)  
Password: string (Required), contains uppercase, lowercase, numbers, and non-letter characters

#### Login Request
```
  {
    "email": "email@example.com",
    "password": "Password123@"
  }
```
Email: string (Required)  
Password: string (Required), contains uppercase, lowercase, numbers, and non-letter characters

#### Access Token Response
```
  {
    "tokenType": "bearer",
    "accessToken": "token",
    "expiresIn": 60,
    "refreshToken": "Ignore This"
  }
```
Token Type: string  
Access Token: string, a set of characters that represents your identity. Use this in the authorization header for the endpoint that needs it.  
Expires In: int, time in seconds of when the token will expire. (60s)  
Refresh Token: string, just ignore this.

#### URL Response
```
{
  "id": 2,
  "createdAt": "2025-05-02T12:55:06.961584",
  "originalUrl": "https://www.verylong.com/xxsaxsaxasxakjxsiajoxjsojxaodsadasdasdasds",
  "shortenedUrl": "https://localhost:7000/verylong2"
}
```
Id: int, id of URL shortening that can be used when accessing /id/{id} endpoint.  
CreatedAt: string, formatted as date-time, that indicates when the shortening was created.  
OriginalUrl: string, the original long URL.  
ShortenedUrl: string, the shortened URL.

#### URL Responses
```
  [
    {
      "id": 1,
      "createdAt": "2025-05-01T12:55:06.961584",
      "originalUrl": "https://www.verylong.com/xxsaxsaxasxakjxsiajoxjsojxaojskajxas",
      "shortenedUrl": "https://localhost:7000/verylong"
    },
    {
      "id": 2,
      "createdAt": "2025-05-02T12:55:06.961584",
      "originalUrl": "https://www.verylong.com/xxsaxsaxasxakjxsiajoxjsojxaodsadasdasdasds",
      "shortenedUrl": "https://localhost:7000/verylong2"
    }
  ]
```
An array of [URL Response](#url-response).  

### Access Token
Access token obtained from the `/login` endpoint will automatically expire after some time and cannot be used again as a bearer token.  
Manual token expiration can be done by hitting the `/logout` endpoint. The included bearer token will expire internally regardless of its duration and cannot be used again as a bearer token.

### Technical Notes on Access Token
The access tokens generated by the `/login` endpoint are stored inside a token manager. The token manager holds a list of tokens and their expiration status. The access token's manual expiration that happens when accessing the `/logout` endpoint is done by setting the expiration status to true.  
The token is currently only stored in the app and not stored in a DB, so when the app is exited or restarted, the record of the token is removed and if the token has been manually expired before, and if its duration is not expired yet, it can be used again as a bearer token.  
I don't know if this is a correct implementation of bearer token expiration. But yeah, this is part of my learning, so if I find a better solution, I should implement it.
