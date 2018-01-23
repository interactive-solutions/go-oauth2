# go-oauth2
Go oauth2 library that is still a work in progress.

## Features
- Provides a token repository for storing tokens in Postgres using 
<cite>[go-pg][0]</cite>.
- Allows the use of custom grants by specifying your own `OauthGrant` and
adding it to the server config.

## Installing
`glide get github.com/interactive-solutions/go-oauth2`

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
    
    // Server will panic if we don't give it a token repository
    s := server.NewDefaultOauthServer(tokenRepository)
    
    s.Config.Grants = map[oauth2.GrantType]oauth2.OauthGrant{
        oauth2.GrantTypePassword:     grant.NewPasswordGrant(passwordAuthorizationHandler),
        oauth2.GrantTypeRefreshToken: grant.NewRefreshTokenGrant(tokenRepository),
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