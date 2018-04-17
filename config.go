package oauth2

var (
	ServerDefaultConfig = ServerConfig{
		Grants: map[GrantType]OauthGrant{},
		ErrorMap: map[error]OauthError{
			RefreshTokenNotFoundErr: {
				Err:         InvalidGrantErr,
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
	Grants map[GrantType]OauthGrant

	// Authorize the client
	ClientAuthorizedHandler func(clientId, clientSecret string) (bool, error)

	// Can client access scope
	ClientScopeHandler func(clientId string, scopes []string) (bool, error)

	// Error map
	ErrorMap map[error]OauthError
}
