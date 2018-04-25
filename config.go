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

		CallbackPreGrant: func(identifier, ipAddr string) error {
			return nil
		},

		CallbackPostGrant: func(identifier, ipAddr, token string) {

		},

		CallbackPrePersistAccessToken: func(accessToken *AccessToken) error {
			return nil
		},

		CallbackPrePersistRefreshToken: func(refreshToken *RefreshToken) error {
			return nil
		},

		IsBehindProxy: false,
		ProxyIpHeader: "X-Forwarded-For",
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

	CallbackPostGrant              CallbackPostGrant
	CallbackPreGrant               CallbackPreGrant
	CallbackPrePersistAccessToken  CallbackPrePersistAccessToken
	CallbackPrePersistRefreshToken CallbackPrePersistRefreshToken

	// If the server is hiding behind a reverse proxy thus check the headers first
	IsBehindProxy bool
	ProxyIpHeader string
}
