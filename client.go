package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var jwksLock sync.Mutex

func (c *OidcClient) sanitizeToken(token string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9\-_\.]`)
	cleanToken := re.ReplaceAllString(token, "")
	return strings.TrimSpace(cleanToken)
}

func (c *OidcClient) generateRandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func (c *OidcClient) GetScopes() []string {
	return c.requestedScopes
}

func (c *OidcClient) GetScopesAsString() string {
	return strings.Join(c.requestedScopes, "+")
}

func (c *OidcClient) SetScopes(scopes []string) error {
	if len(c.ScopesSupported) > 0 {
		for _, s := range scopes {
			if !contains(c.ScopesSupported, s) {
				return fmt.Errorf("unsupported scope: %q", s)
			}
		}
	}
	c.requestedScopes = scopes
	return nil
}

func (c *OidcClient) MustSetScopes(scopes []string) {
	if err := c.SetScopes(scopes); err != nil {
		panic(err)
	}
}

func (c *OidcClient) Introspect(token string) (map[string]interface{}, error) {
	if c.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("introspection endpoint not set")
	}

	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	token = c.sanitizeToken(token)
	data := url.Values{}
	data.Set("token", token)
	reqBody := data.Encode()

	req, err := http.NewRequest("POST", c.IntrospectionEndpoint, strings.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(c.clientId, c.clientSecret)

	resp, err := c.httpClient.Do(req)
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

func (c *OidcClient) Validate(token string) (map[string]interface{}, error) {
	if c.Jwks == nil {
		if _, err := c.getJwks(); err != nil {
			return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
		}
	}

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("unable to find key id in JWT header")
		}

		for _, jwk := range *c.Jwks {
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

	alg := parsed.Header["alg"]
	if algStr, ok := alg.(string); ok {
		if !c.isIdTokenAlgSupported(algStr) {
			return nil, fmt.Errorf("id_token signing algorithm %q is not supported", algStr)
		}
	}

	if exp, ok := claims["exp"].(float64); ok {
		expiry := time.Unix(int64(exp), 0)
		if time.Now().After(expiry) {
			return nil, fmt.Errorf("token expired at %s", expiry)
		}
	}

	if err := claims.Valid(); err != nil {
		return nil, fmt.Errorf("claims validation failed: %w", err)
	}

	return claims, nil
}

func (c *OidcClient) Authorize() {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("Failed to acquire a port: %v", err)
	}

	addr := listener.Addr().(*net.TCPAddr)
	port := addr.Port
	c.redirectURI = fmt.Sprintf("http://localhost:%d/callback", port)

	mux := http.NewServeMux()
	mux.HandleFunc("/", c.loginHandler)
	mux.HandleFunc("/callback", c.callbackHandler)

	c.httpContext, c.httpCancel = context.WithCancel(context.Background())

	server := &http.Server{
		Handler: mux,
	}
	c.httpServer = server

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	authEndpoint := fmt.Sprintf("http://localhost:%d/", port)
	log.Printf("Open the following URL in your browser: %s", authEndpoint)

	<-c.httpContext.Done()
	_ = c.httpServer.Shutdown(context.Background())
}

func (c *OidcClient) Exchange(grant_type, username, password string) (*OidcToken, error) {
	if grant_type == "" || username == "" || password == "" {
		return nil, fmt.Errorf("grant_type, username and password are required")
	}

	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	if !c.isGrantTypeSupported(grant_type) {
		return nil, fmt.Errorf("grant_type %q is not supported by the OIDC provider", grant_type)
	}

	switch grant_type {
	case "password":
		if len(c.requestedScopes) == 0 {
			return nil, fmt.Errorf("at least one scope is required")
		}

		if c.clientId == "" || c.clientSecret == "" || c.TokenEndpoint == "" {
			return nil, fmt.Errorf("client_id, client_secret, and token endpoint are required")
		}

		req, err := http.NewRequest("POST", c.TokenEndpoint, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		body := fmt.Sprintf(
			"grant_type=password&client_id=%s&client_secret=%s&username=%s&password=%s&scope=%s",
			c.clientId, c.clientSecret, username, password, c.GetScopesAsString(),
		)
		req.Body = io.NopCloser(strings.NewReader(body))

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		token := &OidcToken{}
		err = json.Unmarshal(bodyBytes, token)
		if err != nil {
			return nil, err
		}
		return token, nil

	case "client_credentials":
		if c.clientId == "" {
			return nil, fmt.Errorf("client identitifier not set")
		}

		if c.clientSecret == "" {
			return nil, fmt.Errorf("client secret not set")
		}

		if c.TokenEndpoint == "" {
			return nil, fmt.Errorf("unable to obtain token endpoint")
		}

		if len(c.requestedScopes) == 0 {
			return nil, fmt.Errorf("scopes not set")
		}

		req, err := http.NewRequest("POST", c.TokenEndpoint, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
		therequest := fmt.Sprintf("grant_type=%s&client_id=%s&scope=%s", grant_type, c.clientId, c.GetScopesAsString())
		req.Body = io.NopCloser(strings.NewReader(therequest))

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		token := &OidcToken{}
		err = json.Unmarshal(body, token)
		if err != nil {
			return nil, err
		}
		return token, nil

	case "refresh_token":
		if c.clientId == "" {
			return nil, fmt.Errorf("client identitifier not set")
		}

		if c.clientSecret == "" {
			return nil, fmt.Errorf("client secret not set")
		}

		if c.TokenEndpoint == "" {
			return nil, fmt.Errorf("unable to obtain token endpoint")
		}

		req, err := http.NewRequest("POST", c.TokenEndpoint, nil)
		if err != nil {
			log.Printf("There was an error creating the request: %s", err)
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		therequest := fmt.Sprintf("grant_type=%s&client_id=%s&refresh_token=%s&scope=%s", grant_type, c.clientId, username, c.GetScopesAsString())

		req.Body = io.NopCloser(strings.NewReader(therequest))

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		token := &OidcToken{}
		err = json.Unmarshal(body, token)
		if err != nil {
			return nil, err
		}
		return token, nil

	case "authorization_code":
		if c.clientId == "" {
			return nil, fmt.Errorf("client identitifier not set")
		}

		if c.clientSecret == "" {
			return nil, fmt.Errorf("client secret not set")
		}

		if c.TokenEndpoint == "" {
			return nil, fmt.Errorf("unable to obtain token endpoint")
		}

		req, err := http.NewRequest("POST", c.TokenEndpoint, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		therequest := fmt.Sprintf("grant_type=%s&client_id=%s&client_secret=%s&code=%s&scope=%s", grant_type, c.clientId, c.clientSecret, username, c.GetScopesAsString())
		req.Body = io.NopCloser(strings.NewReader(therequest))

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		token := &OidcToken{}
		err = json.Unmarshal(body, token)
		if err != nil {
			return nil, err
		}
		return token, nil

	case "urn:ietf:params:oauth:grant-type:device_code":
		if c.clientId == "" {
			return nil, fmt.Errorf("client identifier not set")
		}

		if c.DeviceAuthorizationEndpoint == "" {
			return nil, fmt.Errorf("device code endpoint not set")
		}

		form := url.Values{}
		form.Set("client_id", c.clientId)
		form.Set("scope", c.GetScopesAsString())

		req, err := http.NewRequest("POST", c.DeviceAuthorizationEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("device code endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
		}

		var deviceResp OidcDeviceCode
		if err := json.NewDecoder(resp.Body).Decode(&deviceResp); err != nil {
			return nil, err
		}

		fmt.Printf("To authenticate, visit: %s\n", deviceResp.VerificationURIComplete)
		fmt.Printf("Or go to: %s and enter code: %s\n", deviceResp.VerificationURI, deviceResp.UserCode)

		pollInterval := time.Duration(deviceResp.Interval) * time.Second
		expiry := time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second)

		for time.Now().Before(expiry) {
			time.Sleep(pollInterval)

			form := url.Values{}
			form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
			form.Set("device_code", deviceResp.DeviceCode)
			form.Set("client_id", c.clientId)

			req, err := http.NewRequest("POST", c.TokenEndpoint, strings.NewReader(form.Encode()))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := c.httpClient.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				var token OidcToken
				if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
					return nil, err
				}
				return &token, nil
			}

			var errResp struct {
				Error string `json:"error"`
			}
			json.NewDecoder(resp.Body).Decode(&errResp)

			switch errResp.Error {
			case "authorization_pending":
				continue
			case "slow_down":
				pollInterval += 5 * time.Second
				continue
			default:
				return nil, fmt.Errorf("token polling failed: %s", errResp.Error)
			}
		}

		return nil, fmt.Errorf("device authorization expired")

	default:
		return nil, fmt.Errorf("unsupported grant_type: %s", grant_type)
	}

}

func (c *OidcClient) UserInfo(accessToken string) (map[string]interface{}, error) {
	if c.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("userinfo endpoint not set")
	}

	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	req, err := http.NewRequest("GET", c.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo error HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *OidcClient) Revoke(token, tokenTypeHint string) error {
	if c.RevocationEndpoint == "" {
		return fmt.Errorf("revocation endpoint not set")
	}

	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	data := url.Values{}
	data.Set("token", token)
	if tokenTypeHint != "" {
		data.Set("token_type_hint", tokenTypeHint)
	}

	req, err := http.NewRequest("POST", c.RevocationEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.clientId, c.clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revocation failed HTTP %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *OidcClient) EndSession(idTokenHint, postLogoutRedirectURI string) error {
	if c.EndSessionEndpoint == "" {
		return fmt.Errorf("end session endpoint not set")
	}

	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	params := url.Values{}
	if idTokenHint != "" {
		params.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirectURI != "" {
		params.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}

	logoutURL := c.EndSessionEndpoint + "?" + params.Encode()

	req, err := http.NewRequest("GET", logoutURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create logout request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("logout request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("logout failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *OidcClient) getJwks() (*[]JWK, error) {
	jwksLock.Lock()
	defer jwksLock.Unlock()

	req, err := http.NewRequestWithContext(context.Background(), "GET", c.JwksUri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
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
	c.Jwks = &jwksData.Keys

	return &jwksData.Keys, nil
}

func contains(supported []string, value string) bool {
	for _, v := range supported {
		if v == value {
			return true
		}
	}
	return false
}

func (c *OidcClient) isGrantTypeSupported(gt string) bool {
	if len(c.GrantTypesSupported) == 0 {
		return true
	}
	return contains(c.GrantTypesSupported, gt)
}

func (c *OidcClient) isResponseTypeSupported(rt string) bool {
	if len(c.ResponseTypesSupported) == 0 {
		return true
	}
	return contains(c.ResponseTypesSupported, rt)
}

func (c *OidcClient) isIdTokenAlgSupported(alg string) bool {
	if len(c.IdTokenSigningAlgValuesSupported) == 0 {
		return true
	}
	return contains(c.IdTokenSigningAlgValuesSupported, alg)
}

func (c *OidcClient) callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != c.clientState {
		http.Error(w, "invalid state parameter", http.StatusBadRequest)
		return
	}

	token, err := c.Exchange("authorization_code", code, "")
	if err != nil {
		log.Printf("token exchange failed: %v", err)
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	log.Printf("access token: %s", token.AccessToken)

	if c.httpCancel != nil {
		c.httpCancel()
	}
}

func (c *OidcClient) loginHandler(w http.ResponseWriter, r *http.Request) {
	if c.redirectURI == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !c.isResponseTypeSupported("code") {
		http.Error(w, "response_type 'code' not supported", http.StatusBadRequest)
		return
	}

	c.clientState = c.generateRandomString(32)

	url := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s",
		c.AuthorizationEndpoint, url.QueryEscape(c.clientId), url.QueryEscape(c.redirectURI), c.GetScopesAsString(), c.clientState)

	http.Redirect(w, r, url, http.StatusFound)
}
