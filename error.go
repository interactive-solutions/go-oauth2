package oauth2

type OauthError struct {
	Error       OauthErrorType `json:"error"`
	Description string         `json:"error_description"`
}

func NewError(error OauthErrorType, description string) *OauthError {
	return &OauthError{
		Error:       error,
		Description: description,
	}
}

type OauthErrorType string

const (
	InvalidRequestErr          OauthErrorType = "invalid_request"
	UnauthorizedClientErr                     = "unauthorized_client"
	InvalidClientErr                          = "invalid_client"
	AccessDeniedErr                           = "access_denied"
	UnsupportedResponseTypeErr                = "unsupported_response_type"
	InvalidScopeErr                           = "invalid_scope"
	InvalidGrantErr                           = "invalid_grant"
	UnsupportedGrantTypeErr                   = "unsupported_grant_type"
	UnsupportedTokenTypeErr                   = "unsupported_token_type"
	ServerErrorErr                            = "server_error"
	TemporarilyUnavailableErr                 = "temporarily_unavailable"
)
