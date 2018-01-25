# go-oauth2
Go oauth2 library that is still a work in progress.

## Features
- Provides a token repository for storing tokens in Postgres using 
<cite>[go-pg][0]</cite>.
- Allows the use of custom grants by specifying your own `OauthGrant` and
adding it to the server config.


## Install
Using glide:
`glide get github.com/interactive-solutions/go-oauth2`

or

`go get github.com/interactive-solutions/go-oauth2`

## Customizing grants
The grant interface looks like this:
```go
type OauthGrant interface {
    // Create and persist authorization code to storage
    CreateAuthorizationCode(r *http.Request, clientId string) (*AuthorizationCode, error)
    // Create and persist tokens to storage
    CreateTokens(r *http.Request, clientId string) (*AccessToken, *RefreshToken, error)
    // Allow public clients ?
    AllowPublicClients() bool
}
```

See the implementation of existing grants for better detail on how to implement your own grant.

For example if we would like to implement Facebook login as a custom grant could look like this:
```go
type facebookGrant struct {
    tokenRepository oauth2.TokenRepository
}
 
func NewFacebookGrant(tokenRepository oauth2.TokenRepository) oauth2.OauthGrant {
    return &facebookGrant{tokenRepository}
}
 
func (grant *facebookGrant) CreateAuthorizationCode(r *http.Request, clientId string) (*oauth2.AuthorizationCode, error) {
    return nil, oauth2.NewError(oauth2.InvalidRequestErr, "Facebook grant does not support authorization")
}
 
func (grant *facebookGrant) CreateTokens(r *http.Request, clientId string) (*oauth2.AccessToken, *oauth2.RefreshToken, error) {
    token := r.FormValue("token")
    
    if token == "" {
        return nil, nil, oauth2.NewError(oauth2.InvalidRequestErr, "Missing token in request")
    }
    
    user, err := // get user from facebook token
    if err != nil {
        return nil, nil, oauth2.NewError(oauth2.AccessDeniedErr, "Unable to retrieve user from token")
    }
    
    var accessToken *oauth2.AccessToken
    var refreshToken *oauth2.RefreshToken
    var err error
    
    // Generate access token until it is unique
    for {
        accessToken = oauth2.NewAccessToken(clientId, oauth2.OauthTokenOwnerId(user.Id), time.Hour, []string{})
        
        if t, _ := grant.tokenRepository.GetAccessToken(accessToken.Token); t == nil {
            break
        }
    }
    
    if err := grant.tokenRepository.CreateAccessToken(accessToken); err != nil {
        return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, err.Error())
    }
    
    // Generate a refresh token until it is unique
    for {
        refreshToken = oauth2.NewRefreshToken(clientId, oauth2.OauthTokenOwnerId(user.Id), backend.RefreshTokenDuration, []string{})

        if t, _ := grant.tokenRepository.GetRefreshToken(refreshToken.Token); t == nil {
            break
        }
    }
    
    if err = grant.tokenRepository.CreateRefreshToken(refreshToken); err != nil {
        return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, err.Error())
    }
    
    return accessToken, refreshToken, nil
}
 
func (grant *facebookGrant) AllowPublicClients() bool {
    return true
}
```

## Setup
```go
import (
    "errors"
    "net/http"
	
    "github.com/interactive-solutions/go-oauth2/server"
    "github.com/interactive-solutions/go-oauth2/token"
    "github.com/interactive-solutions/go-oauth2"
    "github.com/go-pg/pg"
)
 
func main() {    
    // If you want to use the built in token repository, connect to postgres
    // using go-pg
    database := pg.Connect(&pg.Options{
        User:     "user",
        Addr:     fmt.Sprintf("%s:%s", "localhost", "5432"),
        Password: "password",
        Database: "database",
    })
    
    var n int
    _, err := database.QueryOne(pg.Scan(&n), "SELECT 1")
    if err != nil {
        panic(err)
    }
    
    tokenRepository := token.NewTokenRepository(database)
    
    userIsBlockedErr := errors.New("User is blocked")
    
    passwordAuthorizationHandler := func (username, password string) (oauth2.OauthTokenOwnerId, error) {
        // Dummy authorization handler
        if username != "username" || password != "password" {
            return "", oauth2.NewError(oauth2.AccessDenied, "Invalid credentials")
        }
        
        // Custom error, see error map config below
        if username == "blocked" {
            return "", userIsBlockedErr
        }
        
        return "12345", nil
    }
    
    s := server.NewDefaultOauthServer(tokenRepository)
    
    s.Config.Grants = map[oauth2.GrantType]oauth2.OauthGrant{
        oauth2.GrantTypePassword: grant.NewPasswordGrant(
            handler.passwordAuthorization,
            tokenRepository,
            grant.PasswordGrantDefaultConfig,
        ),
        oauth2.GrantTypeRefreshToken: grant.NewRefreshTokenGrant(tokenRepository, grant.RefreshTokenGrantDefaultConfig),
        "facebook": NewFacebookGrant(tokenRepository),
    }
    
    // Map a custom error to an error specified in the documentation
    s.Config.ErrorMap[userIsBlockedErr] = oauth2.OauthError {
        Err: oauth2.AccessDenied,
        Description: "Invalid credentials"
    }
    
    http.HandleFunc("/oauth/token", func (w http.ResponseWriter, r *http.Request) {
        s.HandleTokenRequest(w, r)
    })
}
```

## Todo
- ensure the oauth2 standard is followed correctly
- implement remaining grants
- tests
- improved docs

[0]:https://github.com/go-pg/pg