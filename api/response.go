package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"strings"

	"math"

	"github.com/interactive-solutions/go-oauth2"
)

func WriteTokenResponse(
	w http.ResponseWriter,
	accessToken *oauth2.OauthAccessToken,
	refreshToken *oauth2.OauthRefreshToken,
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
		ExpiresIn    float64          `json:"expires_in"`
		Scopes       string           `json:"scope"`
		OwnerId      interface{}      `json:"owner_id,omitempty"`
	}{
		AccessToken: accessToken.Token,
		TokenType:   oauth2.TokenTypeBearer,
		ExpiresIn:   math.Floor(accessToken.GetExpiresIn()),
		Scopes:      strings.Join(scopes, " "),
	}

	if accessToken.OwnerId != "" {
		payload.OwnerId = accessToken.OwnerId
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

func WriteErrorResponse(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	oauthError, ok := err.(*oauth2.OauthError)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf(err.Error())))
		return
	}

	body, err := json.Marshal(oauthError.Description)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("Failed to create response: %s", err)))
		return
	}

	// From specification
	// "The authorization server responds with an HTTP 400 (Bad Request)
	// status code (unless specified otherwise)"
	switch oauthError.Err {
	case oauth2.ServerErrorErr:
		w.WriteHeader(http.StatusInternalServerError)
	case oauth2.TemporarilyUnavailableErr:
		w.WriteHeader(http.StatusServiceUnavailable)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}

	w.Write(body)
}