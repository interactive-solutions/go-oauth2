package grant

type PasswordGrantConfig struct {
	// Should we generate a refresh token for each access token ?
	GenerateRefreshToken bool
}

type RefreshTokenGrantConfig struct {
	// Should a new refresh token be generated when refresh_token grant is used
	RotateRefreshTokens bool
	// Should the old refresh token be revoked if the refresh token rotated
	RevokeRotatedRefreshTokens bool
}
