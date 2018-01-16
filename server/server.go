package server

import (
	"net/http"

	"fmt"

	"strings"

	"encoding/base64"

	"github.com/interactive-solutions/go-oauth2"
	"github.com/interactive-solutions/go-oauth2/api"
	"github.com/interactive-solutions/go-oauth2/grant"
	"github.com/interactive-solutions/go-oauth2/model"
	"github.com/pkg/errors"
)

type OauthServer struct {
	ClientService oauth2.ClientService
	Config        ServerConfig
	ResponseTypes map[oauth2.ResponseType]grant.OauthGrant
}

func NewDefaultOauthServer() *OauthServer {
	return NewOauthServer(ServerDefaultConfig)
}

func NewOauthServer(config ServerConfig) *OauthServer {
	responseTypes := map[oauth2.ResponseType]grant.OauthGrant{}
	for _, oauthGrant := range config.Grants {
		if oauthGrant.GetResponseType() != "" {
			responseTypes[oauthGrant.GetResponseType()] = oauthGrant
		}
	}

	return &OauthServer{
		Config:        config,
		ResponseTypes: responseTypes,
	}
}

// Get grant by name
func (server *OauthServer) getGrant(grantType oauth2.GrantType) (grant.OauthGrant, oauth2.OauthErr, string) {
	for _, oauthGrant := range server.Config.Grants {
		if oauthGrant.GetType() == grantType {
			return oauthGrant, oauth2.OauthErrNil, ""
		}
	}

	return nil, oauth2.UnsupportedGrantTypeErr, fmt.Sprintf("Grant type %s is not supported by this server", grantType)
}

// Get response type by its name
func (server *OauthServer) getResponseType(responseType oauth2.ResponseType) (grant.OauthGrant, oauth2.OauthErr, string) {
	if oauthGrant, ok := server.ResponseTypes[responseType]; ok {
		return oauthGrant, oauth2.OauthErrNil, ""
	}

	return nil, oauth2.UnsupportedResponseTypeErr, fmt.Sprintf("Response type %s is not supported by this server", responseType)
}

// Get the client (after authenticating it)
func (server *OauthServer) getClient(r *http.Request, allowPublicClients bool) (*model.OauthClient, oauth2.OauthErr, string) {
	clientId, clientSecret, err := server.extractClientCredentialsFromRequest(r)
	if err != nil {
		return nil, oauth2.InvalidRequestErr, err.Error()
	}

	// If the grant type we are issuing does not allow public clients, and that the secret is
	// missing, then we have an error...
	if !allowPublicClients && clientSecret == "" {
		return nil, oauth2.InvalidClientErr, "Client secret is missing"
	}

	// If we allow public clients, no client is required
	if allowPublicClients && clientId == "" {
		return nil, oauth2.OauthErrNil, ""
	}

	client, err := server.ClientService.GetClientById(clientId)
	if err != nil {
		return nil, oauth2.InvalidClientErr, "Client authentication failed"
	}

	if !allowPublicClients && !client.Authenticate(clientSecret) {
		return nil, oauth2.InvalidClientErr, "Client authentication failed"
	}

	return client, oauth2.OauthErrNil, ""
}

func (server *OauthServer) extractClientCredentialsFromRequest(r *http.Request) (string, string, error) {
	// We first try to get the Authorization header, as this is the recommended way according to the spec
	if r.Header.Get("Authorization") != "" {
		// The value is "Basic xxx", we are interested in the last part
		parts := strings.Split(r.Header.Get("Authorization"), " ")
		if strings.ToLower(parts[0]) != "basic" || len(parts) != 2 {
			return "", "", errors.New("Invalid basic authentication header")
		}

		value, err := base64.StdEncoding.DecodeString(parts[len(parts)-1])
		if err != nil {
			return "", "", err
		}

		parts = strings.Split(string(value), ":")
		if len(parts) != 2 {
			return "", "", errors.New("Malformed basic authentication header")
		}

		return parts[0], parts[1], nil
	}

	clientId := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	return clientId, clientSecret, nil
}

func (server *OauthServer) SetAllowedGrants(grants []grant.OauthGrant) {
	server.Config.Grants = grants

	responseTypes := map[oauth2.ResponseType]grant.OauthGrant{}
	for _, oauthGrant := range server.Config.Grants {
		if oauthGrant.GetResponseType() != "" {
			responseTypes[oauthGrant.GetResponseType()] = oauthGrant
		}
	}

	server.ResponseTypes = responseTypes
}

func (server *OauthServer) HandleAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	responseType := r.FormValue("response_type")

	if responseType == "" {
		api.WriteErrorResponse(w, oauth2.InvalidRequestErr, "No grant response type was found in request")
		return
	}
}

func (server *OauthServer) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")

	if grantType == "" {
		api.WriteErrorResponse(w, oauth2.InvalidRequestErr, "No grant type was found in the request")
		return
	}

	oauthGrant, oauthError, errorDescription := server.getGrant(oauth2.GrantType(grantType))
	if oauthError != oauth2.OauthErrNil {
		api.WriteErrorResponse(w, oauthError, errorDescription)
		return
	}

	client, oauthError, errorDescription := server.getClient(r, oauthGrant.AllowPublicClients())
	if oauthError != oauth2.OauthErrNil {
		api.WriteErrorResponse(w, oauthError, errorDescription)
		return
	}

	oauthGrant.HandleTokenRequest(w, r, client, nil)
}
