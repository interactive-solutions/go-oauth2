package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"time"

	"strings"

	"github.com/interactive-solutions/go-oauth2"
	"github.com/interactive-solutions/go-oauth2/token"
)

func WriteTokenResponse(
	w http.ResponseWriter,
	accessToken *token.OauthAccessToken,
	refreshToken *token.OauthRefreshToken,
	useRefreshTokenScopes bool,
) {
	w.Header().Set("Content-Type", "application/json")

	scopes := accessToken.Scopes
	if useRefreshTokenScopes {
		scopes = refreshToken.Scopes
	}

	payload := struct {
		AccessToken  string           `json:"access_token"`
		RefreshToken string           `json:"refresh_token,omitempty"`
		TokenType    oauth2.TokenType `json:"token_type"`
		ExpiresIn    time.Duration    `json:"expires_in"`
		Scopes       string           `json:"scope"`
		OwnerId      interface{}      `json:"owner_id,omitempty"`
	}{
		AccessToken: accessToken.Token,
		TokenType:   oauth2.TokenTypeBearer,
		ExpiresIn:   time.Until(accessToken.ExpiresAt),
		Scopes:      strings.Join(scopes, " "),
	}

	if accessToken.Owner != nil {
		payload.OwnerId = accessToken.Owner.GetId()
	}

	if refreshToken != nil {
		payload.RefreshToken = refreshToken.Token
	}

	body, err := json.Marshal(&payload)
	if err != nil {
		WriteErrorResponse(w, oauth2.NewError(oauth2.ServerErrorErr, "Failed to create token response"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func WriteErrorResponse(w http.ResponseWriter, error *oauth2.OauthError) {
	w.Header().Set("Content-Type", "application/json")

	body, err := json.Marshal(error)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("Failed to create response: %s", err)))
		return
	}

	// From specification
	// "The authorization server responds with an HTTP 400 (Bad Request)
	// status code (unless specified otherwise)"
	switch error.Error {
	case oauth2.ServerErrorErr:
		w.WriteHeader(http.StatusInternalServerError)
	case oauth2.TemporarilyUnavailableErr:
		w.WriteHeader(http.StatusServiceUnavailable)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}

	w.Write(body)
}
