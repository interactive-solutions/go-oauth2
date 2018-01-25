package server

import (
	"github.com/interactive-solutions/go-oauth2"
)

// todo: implement this

var (
	ServerDefaultConfig = ServerConfig{
		Grants: map[oauth2.GrantType]oauth2.OauthGrant{},
		ErrorMap: map[error]oauth2.OauthError{
			oauth2.RefreshTokenNotFoundErr: {
				Err:         oauth2.InvalidGrantErr,
				Description: "Refresh has expired or been deleted",
			},
		},
		ClientAuthorizedHandler: func(clientId, clientSecret string) (bool, error) {
			return true, nil
		},
		ClientScopeHandler: func(clientId string, scopes []string) (bool, error) {
			return true, nil
		},
	}
)

type ServerConfig struct {
	// Grants
	Grants map[oauth2.GrantType]oauth2.OauthGrant

	// Authorize the client
	ClientAuthorizedHandler func(clientId, clientSecret string) (bool, error)

	// Can client access scope
	ClientScopeHandler func(clientId string, scopes []string) (bool, error)

	// Error map
	ErrorMap map[error]oauth2.OauthError
}
