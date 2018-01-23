package oauth2

import "github.com/pkg/errors"

type OauthError struct {
	Err         OauthErrorType `json:"error"`
	Description string         `json:"error_description"`
}

func (e OauthError) Error() string {
	return e.Description
}

func NewError(error OauthErrorType, description string) error {
	return OauthError{
		Err:         error,
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

var (
	AccessTokenNotFoundErr  = errors.New("Access token not found")
	RefreshTokenNotFoundErr = errors.New("Refresh token not found")
)
