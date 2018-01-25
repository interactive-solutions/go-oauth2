package grant

import "time"

func NewDefaultPasswordGrantConfig() PasswordGrantConfig {
	return PasswordGrantConfig{
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: time.Hour * 24,
		GenerateRefreshToken: true,
	}
}

type PasswordGrantConfig struct {
	// Durations for tokens
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration

	// Should we generate a refresh token for each access token ?
	GenerateRefreshToken bool
}

func NewDefaultRefreshTokenGrantConfig() RefreshTokenGrantConfig {
	return RefreshTokenGrantConfig{
		AccessTokenDuration:        time.Hour,
		RefreshTokenDuration:       time.Hour * 24,
		RotateRefreshTokens:        false,
		RevokeRotatedRefreshTokens: false,
	}
}

type RefreshTokenGrantConfig struct {
	// Duration for tokens
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration

	// Should we generate a new refresh token after calling refresh token grant ?
	RotateRefreshTokens bool

	// Should we revoke a rotated refresh token ?
	RevokeRotatedRefreshTokens bool
}

func NewDefaultClientCredentialsGrantConfig() ClientCredentialsGrantConfig {
	return ClientCredentialsGrantConfig{AccessTokenDuration: time.Hour}
}

type ClientCredentialsGrantConfig struct {
	// Duration for tokens
	AccessTokenDuration time.Duration
}
