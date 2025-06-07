package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
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
	clientId                          string
	clientSecret                      string
}

func (o *OidcClient) Introspect(token string) (map[string]interface{}, error) {
	if o.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("introspection endpoint not set")
	}

	token = sanitizeToken(token)
	log.Printf("Validating token: %s", token)
	data := url.Values{}
	data.Set("token", token)
	reqBody := data.Encode()

	req, err := http.NewRequest("POST", o.IntrospectionEndpoint, strings.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(o.clientId, o.clientSecret)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call introspection endpoint: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read introspection response: %v", err)
	}

	log.Printf("Introspection response body: %s", string(body))
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse introspection response: %v", err)
	}

	if active, ok := result["active"].(bool); !ok || !active {
		return nil, fmt.Errorf("token is not valid")
	}

	sub, ok := result["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("sub not found in token claims")
	}

	log.Printf("Token is valid. Username: %s", sub)
	return result, nil
}

func (o *OidcClient) Validate(token string) (map[string]interface{}, error) {
	if o.Jwks == nil {
		if _, err := o.getJwks(); err != nil {
			return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
		}
	}

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("JWT missing kid header")
		}

		for _, jwk := range *o.Jwks {
			if jwk.Kid != kid {
				continue
			}
			switch jwk.Kty {
			case "RSA":
				return jwk.rsaPublicKey()
			case "EC":
				return jwk.ecdsaPublicKey()
			default:
				return nil, fmt.Errorf("unsupported key type %q", jwk.Kty)
			}
		}
		return nil, fmt.Errorf("unable to find key %q in JWKS", kid)
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("JWT parse/verify failed: %w", err)
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("JWT invalid")
	}
	if err := claims.Valid(); err != nil {
		return nil, fmt.Errorf("claims validation failed: %w", err)
	}

	return claims, nil
}

func (c *OidcClient) Exchange(grant_type, username, password string, scopes []string) *OidcExchangeResponse {
	if grant_type == "" || username == "" || password == "" {
		return nil
	}

	if grant_type == "client_credentials" {
		client := &http.Client{}
		req, err := http.NewRequest("POST", c.TokenEndpoint, nil)
		if err != nil {
			log.Printf("There was an error creating the request: %s", err)
			return nil
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		thescopes := strings.Join(scopes, "+")
		therequest := fmt.Sprintf("grant_type=%s&client_id=%s&username=%s&password=%s&scope=%s", grant_type, c.clientId, username, password, thescopes)
		log.Printf("-- ThE REQUEST: %s", therequest)
		req.Body = io.NopCloser(strings.NewReader(therequest))
		log.Printf("Exchange request body: %s", req.Body)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("There was an error calling the token endpoint: %s", err)
			return nil
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("There was an error reading the response body: %s", err)
			return nil
		}

		log.Printf("Exchange response body: %s", string(body))
		token := &OidcExchangeResponse{}
		err = json.Unmarshal(body, token)
		if err != nil {
			log.Printf("There was an error unmarshalling the response body: %s", err)
			return nil
		}
		return token
	}

	if grant_type == "refresh_token" {
		client := &http.Client{}
		req, err := http.NewRequest("POST", c.TokenEndpoint, nil)
		if err != nil {
			log.Printf("There was an error creating the request: %s", err)
			return nil
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		thescopes := strings.Join(scopes, "+")
		therequest := fmt.Sprintf("grant_type=%s&client_id=%s&refresh_token=%s&scope=%s", grant_type, c.clientId, username, thescopes)
		log.Printf("-- ThE REQUEST: %s", therequest)
		req.Body = io.NopCloser(strings.NewReader(therequest))
		log.Printf("Exchange request body: %s", req.Body)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("There was an error calling the token endpoint: %s", err)
			return nil
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("There was an error reading the response body: %s", err)
			return nil
		}
		log.Printf("Exchange response body: %s", string(body))
		token := &OidcExchangeResponse{}
		err = json.Unmarshal(body, token)
		if err != nil {
			log.Printf("There was an error unmarshalling the response body: %s", err)
			return nil
		}
		return token
	}

	return nil
}

type OidcExchangeResponse struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
}

func (o *OidcClient) getJwks() (*[]JWK, error) {
	jwksLock.Lock()
	defer jwksLock.Unlock()

	req, err := http.NewRequestWithContext(context.Background(), "GET", o.JwksUri, nil)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwksData jwksResponse
	if err := json.Unmarshal(body, &jwksData); err != nil {
		return nil, err
	}
	o.Jwks = &jwksData.Keys

	return &jwksData.Keys, nil
}
