package server

import (
	"net/http"
	"time"

	"github.com/interactive-solutions/go-oauth2"
	"github.com/interactive-solutions/go-oauth2/grant"
)

type RequestValidator func(r *http.Request) (bool, oauth2.OauthErr, string)

var (
	ServerDefaultConfig = ServerConfig{
		AuthorizationCodeDuration:  time.Minute * 2,
		AccessTokenDuration:        time.Hour,
		RefreshTokenDuration:       time.Hour * 24,
		RotateRefreshTokens:        false,
		RevokeRotatedRefreshTokens: true,
		Grants: []grant.OauthGrant{},
	}
)

type ServerConfig struct {
	// Durations before code / token expires
	AuthorizationCodeDuration time.Duration
	AccessTokenDuration       time.Duration
	RefreshTokenDuration      time.Duration

	// Should a new refresh token be generated when refresh_token grant is used
	RotateRefreshTokens bool
	// Should the old refresh token be revoked if the refresh token rotated
	RevokeRotatedRefreshTokens bool

	// Grants
	Grants []grant.OauthGrant
}
