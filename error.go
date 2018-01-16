package oauth2

type OauthErr string

const OauthErrNil OauthErr = ""

const (
	InvalidRequestErr          OauthErr = "invalid_request"
	UnauthorizedClientErr               = "unauthorized_client"
	InvalidClientErr                    = "invalid_client"
	AccessDeniedErr                     = "access_denied"
	UnsupportedResponseTypeErr          = "unsupported_response_type"
	InvalidScopeErr                     = "invalid_scope"
	InvalidGrantErr                     = "invalid_grant"
	UnsupportedGrantTypeErr             = "unsupported_grant_type"
	UnsupportedTokenTypeErr             = "unsupported_token_type"
	ServerErrorErr                      = "server_error"
	TemporarilyUnavailableErr           = "temporarily_unavailable"
)
