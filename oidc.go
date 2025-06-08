package oidc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func NewOidcClient(iss, id, secret string) (*OidcClient, error) {
	url := iss + ".well-known/openid-configuration"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call well-known endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read well-known response: %w", err)
	}

	var result OidcClient
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse well-known response: %w", err)
	}

	if result.TokenEndpoint == "" || result.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("OIDC configuration is incomplete: %+v", result)
	}

	result.httpClient = client

	go func() {
		ticker := time.NewTicker(time.Hour)
		for range ticker.C {
			result.getJwks()
		}
	}()

	result.clientId = id
	result.clientSecret = secret

	return &result, nil
}
