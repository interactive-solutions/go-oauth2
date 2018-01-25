package server

import (
	"net/http"

	"fmt"

	"context"

	"time"

	"strings"

	"github.com/interactive-solutions/go-oauth2"
	"github.com/interactive-solutions/go-oauth2/api"
)

type OauthServer struct {
	Config          ServerConfig
	tokenRepository oauth2.TokenRepository
}

func NewDefaultOauthServer(tokenRepository oauth2.TokenRepository) *OauthServer {
	return NewOauthServer(ServerDefaultConfig, tokenRepository)
}

func NewOauthServer(config ServerConfig, tokenRepository oauth2.TokenRepository) *OauthServer {
	if tokenRepository == nil {
		panic("No token repository given to oauth2 server")
	}

	return &OauthServer{
		Config:          config,
		tokenRepository: tokenRepository,
	}
}

func (server *OauthServer) PeriodicallyDeleteExpiredTokens(ctx context.Context, interval time.Duration) {
	timer := time.NewTimer(0)

	select {
	case <-ctx.Done():
		timer.Stop()
		return
	case <-timer.C:
		server.tokenRepository.DeleteExpiredAccessTokens()
		server.tokenRepository.DeleteExpiredRefreshTokens()

		timer.Reset(interval)
	}
}

// Get grant by name
func (server *OauthServer) getGrant(grantType oauth2.GrantType) (oauth2.OauthGrant, error) {
	if grant, ok := server.Config.Grants[grantType]; ok {
		return grant, nil
	}

	return nil, oauth2.NewError(
		oauth2.UnsupportedGrantTypeErr,
		fmt.Sprintf("Grant type %s is not supported by this server", grantType),
	)
}

// Get the client
func (server *OauthServer) getClient(r *http.Request, allowPublicClients bool) (string, error) {
	clientId, clientSecret, ok := r.BasicAuth()
	if !ok {
		// Could not get client from basic authentication, check form data
		clientId = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	if !allowPublicClients && clientSecret == "" {
		return "", oauth2.NewError(oauth2.InvalidClientErr, "Client secret is missing")
	}

	if allowPublicClients && clientId == "" {
		return "", nil
	}

	// Authorize client if we have a handler set
	if server.Config.ClientAuthorizedHandler != nil {
		authorized, err := server.Config.ClientAuthorizedHandler(clientId, clientSecret)
		if err != nil {
			return "", err
		} else if !authorized {
			return "", oauth2.NewError(oauth2.InvalidClientErr, "Client authentication failed")
		}
	}

	// Check if client can access scope if we have handler set
	if server.Config.ClientScopeHandler != nil && r.FormValue("scope") != "" {
		allowed, err := server.Config.ClientScopeHandler(clientId, strings.Split(r.FormValue("scope"), " "))
		if err != nil {
			return "", err
		}

		if !allowed {
			return "", oauth2.NewError(oauth2.InvalidScopeErr, "Client not allowed to access provided scope")
		}
	}

	// We have no handler set, allow credentials to pass as default
	return clientId, nil
}

func (server *OauthServer) HandleAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	responseType := r.FormValue("response_type")

	if responseType == "" {
		server.writeError(w, oauth2.NewError(oauth2.InvalidRequestErr, "No grant response type was found in request"))
		return
	}
}

func (server *OauthServer) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")

	if grantType == "" {
		server.writeError(w, oauth2.NewError(oauth2.InvalidRequestErr, "No grant type was found in the request"))
		return
	}

	oauthGrant, err := server.getGrant(oauth2.GrantType(grantType))
	if err != nil {
		server.writeError(w, err)
		return
	}

	clientId, err := server.getClient(r, oauthGrant.AllowPublicClients())
	if err != nil {
		server.writeError(w, err)
		return
	}

	accessToken, refreshToken, err := oauthGrant.CreateTokens(r, clientId)
	if err != nil {
		server.writeError(w, err)
		return
	}

	useRefreshTokenScope := false
	if grantType == oauth2.GrantTypeRefreshToken {
		useRefreshTokenScope = true
	}

	api.WriteTokenResponse(w, accessToken, refreshToken, useRefreshTokenScope)
}

func (server *OauthServer) writeError(w http.ResponseWriter, err error) {
	if server.Config.ErrorMap == nil {
		api.WriteErrorResponse(w, err)
		return
	}

	oauthError, ok := server.Config.ErrorMap[err]
	if !ok {
		api.WriteErrorResponse(w, err)
		return
	}

	api.WriteErrorResponse(w, oauthError)
}
