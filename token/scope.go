package token

type OauthScope struct {
	Id          int
	Name        string
	Description string
	IsDefault   bool
}

func NewOauthScope(id int, name string, description string, isDefault bool) *OauthScope {
	return &OauthScope{
		Id:          id,
		Name:        name,
		Description: description,
		IsDefault:   isDefault,
	}
}
