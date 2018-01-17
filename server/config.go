package server

import (
	"time"

	"github.com/interactive-solutions/go-oauth2"
)

var (
	ServerDefaultConfig = ServerConfig{
		AuthorizationCodeDuration: time.Minute * 2,
		AccessTokenDuration:       time.Hour,
		RefreshTokenDuration:      time.Hour * 24,
		Grants:                    []oauth2.OauthGrant{},
	}
)

type ServerConfig struct {
	// Durations before code / token expires
	AuthorizationCodeDuration time.Duration
	AccessTokenDuration       time.Duration
	RefreshTokenDuration      time.Duration

	// Grants
	Grants []oauth2.OauthGrant
}
