package server

import (
	"net/http"

	"fmt"

	"strings"

	"context"

	"time"

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
func (server *OauthServer) getClient(r *http.Request, allowPublicClients bool) (string, string, error) {
	clientId, clientSecret, ok := r.BasicAuth()
	if !ok {
		// Could not get client from basic authentication, check form data
		clientId = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	if !allowPublicClients && clientSecret == "" {
		return "", "", oauth2.NewError(oauth2.InvalidClientErr, "Client secret is missing")
	}

	if allowPublicClients && clientId == "" {
		return "", "", nil
	}

	// Authorize client if we have a handler set
	if server.Config.ClientAuthorizedHandler != nil {
		authorized, err := server.Config.ClientAuthorizedHandler(clientId, clientSecret)
		if err != nil {
			return "", "", err
		} else if !authorized {
			return "", "", oauth2.NewError(oauth2.InvalidClientErr, "Client authentication failed")
		}
	}

	// We have no handler set, allow credentials to pass as default
	return clientId, clientSecret, nil
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

	clientId, clientSecret, err := server.getClient(r, oauthGrant.AllowPublicClients())
	if err != nil {
		server.writeError(w, err)
		return
	}

	tokenOwnerId, err := oauthGrant.Authorize(r, clientId, clientSecret)
	if err != nil {
		server.writeError(w, err)
		return
	}

	scopes := strings.Split(r.FormValue("scope"), " ")
	var refreshToken *oauth2.OauthRefreshToken

	if grantType == oauth2.GrantTypeRefreshToken {
		if r.FormValue("refresh_token") == "" {
			server.writeError(w, oauth2.NewError(oauth2.InvalidRequestErr, "Refresh token is missing"))
			return
		}

		refreshToken, err := server.tokenRepository.GetRefreshToken(r.FormValue("refresh_token"))
		if err != nil {
			server.writeError(w, err)
			return
		}

		if !refreshToken.IsValid(scopes) {
			server.writeError(w, oauth2.NewError(oauth2.InvalidGrantErr, "Refresh expired or has been deleted"))
			return
		}
	}

	accessToken, refreshToken, err := server.createTokens(tokenOwnerId, clientId, scopes, refreshToken)
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

// todo: cleanup
func (server *OauthServer) createTokens(
	tokenOwnerId oauth2.OauthTokenOwnerId,
	clientId string,
	scopes []string,
	refreshToken *oauth2.OauthRefreshToken,
) (*oauth2.OauthAccessToken, *oauth2.OauthRefreshToken, error) {
	var accessToken *oauth2.OauthAccessToken
	var err error

	// Generate new access tokens until we have a unique
	for {
		accessToken, err = oauth2.NewOauthAccessToken(clientId, tokenOwnerId, server.Config.AccessTokenDuration, scopes)
		if err != nil {
			return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, "Error creating access token")
		}

		if t, _ := server.tokenRepository.GetAccessToken(accessToken.Token); t == nil {
			break
		}
	}

	if err = server.tokenRepository.CreateAccessToken(accessToken); err != nil {
		return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, "Error persisting access token")
	}

	// Are we generating tokens using refresh grant ?
	if refreshToken == nil {
		if !server.Config.GenerateRefreshToken {
			return accessToken, nil, nil
		}

		for {
			refreshToken, err := oauth2.NewOauthRefreshToken(clientId, tokenOwnerId, server.Config.RefreshTokenDuration, scopes)
			if err != nil {
				return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, "Error creating refresh token")
			}

			if t, _ := server.tokenRepository.GetRefreshToken(refreshToken.Token); t == nil {
				break
			}
		}

		if err = server.tokenRepository.CreateRefreshToken(refreshToken); err != nil {
			return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, "Error persisting refresh token")
		}

		return accessToken, refreshToken, nil
	}

	if !server.Config.RotateRefreshTokens {
		return accessToken, refreshToken, nil
	}

	var newRefreshToken *oauth2.OauthRefreshToken

	for {
		// Refresh grant and rotating refresh tokens
		newRefreshToken, err = oauth2.NewOauthRefreshToken(clientId, tokenOwnerId, server.Config.RefreshTokenDuration, scopes)
		if err != nil {
			return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, "Error creating refresh token")
		}

		if t, _ := server.tokenRepository.GetRefreshToken(newRefreshToken.Token); t == nil {
			break
		}
	}

	if err = server.tokenRepository.CreateRefreshToken(newRefreshToken); err != nil {
		return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, "Error persisting refresh token")
	}

	if server.Config.RevokeRotatedRefreshTokens {
		if err = server.tokenRepository.DeleteRefreshToken(refreshToken.Token); err != nil {
			return nil, nil, oauth2.NewError(oauth2.ServerErrorErr, "Error cleaning up old refresh token")
		}
	}

	return accessToken, newRefreshToken, nil
}
