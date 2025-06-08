package oidc

import (
	"context"
	"net/http"
	"time"
)

type OidcClient struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	JwksUri                           string   `json:"jwks_uri"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	AcrValuesSupported                []string `json:"acr_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	RequestParameterSupported         bool     `json:"request_parameter_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	ClaimsParameterSupported          bool     `json:"claims_parameter_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	Jwks                              *[]JWK
	Token                             *OidcToken
	clientId                          string
	clientSecret                      string
	clientState                       string
	httpServer                        *http.Server
	httpClient                        *http.Client
	httpContext                       context.Context
	httpCancel                        context.CancelFunc
	requestedScopes                   []string
	redirectURI                       string
}

type OidcDeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type OidcToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	// RSA fields
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC fields
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type jwksResponse struct {
	Keys []JWK `json:"keys"`
}
