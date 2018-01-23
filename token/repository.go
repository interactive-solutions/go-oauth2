package token

import (
	"time"

	"github.com/go-pg/pg"
	"github.com/interactive-solutions/go-oauth2"
)

type tokenRepository struct {
	db *pg.DB
}

func NewTokenRepository(db *pg.DB) oauth2.TokenRepository {
	return &tokenRepository{
		db: db,
	}
}

func (repository *tokenRepository) CreateAccessToken(token *oauth2.OauthAccessToken) error {
	return repository.db.Insert(token)
}

func (repository *tokenRepository) CreateRefreshToken(token *oauth2.OauthRefreshToken) error {
	return repository.db.Insert(token)
}

func (repository *tokenRepository) GetAccessToken(token string) (*oauth2.OauthAccessToken, error) {
	accessToken := &oauth2.OauthAccessToken{}

	err := repository.db.Model(accessToken).Where("token = ?", token).Select()
	if err == pg.ErrNoRows {
		return nil, oauth2.AccessTokenNotFoundErr
	}

	return accessToken, nil
}

func (repository *tokenRepository) GetRefreshToken(token string) (*oauth2.OauthRefreshToken, error) {
	refreshToken := &oauth2.OauthRefreshToken{}

	err := repository.db.Model(refreshToken).Where("token = ?", token).Select()
	if err == pg.ErrNoRows {
		return nil, oauth2.RefreshTokenNotFoundErr
	}

	return refreshToken, nil
}

func (repository *tokenRepository) DeleteAccessToken(token string) error {
	accessToken := &oauth2.OauthAccessToken{}

	_, err := repository.db.Model(accessToken).Where("token = ?", token).Delete()

	return err
}

func (repository *tokenRepository) DeleteRefreshToken(token string) error {
	refreshToken := &oauth2.OauthRefreshToken{}

	_, err := repository.db.Model(refreshToken).Where("token = ?", token).Delete()

	return err
}

func (repository *tokenRepository) DeleteExpiredAccessTokens() error {
	accessToken := &oauth2.OauthAccessToken{}

	_, err := repository.db.Model(accessToken).Where("expires_at < ?", time.Now()).Delete()

	return err
}

func (repository *tokenRepository) DeleteExpiredRefreshTokens() error {
	refreshToken := &oauth2.OauthRefreshToken{}

	_, err := repository.db.Model(refreshToken).Where("expires_at < ?", time.Now()).Delete()

	return err
}
