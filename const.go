package oauth2

type ResponseType string

const (
	ResponseTypeToken ResponseType = "token"
	ResponseTypeCode               = "code"
)

type TokenType string

const (
	TokenTypeBearer TokenType = "Bearer"
)

type GrantType string

const (
	GrantTypePassword          = "password"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
)
