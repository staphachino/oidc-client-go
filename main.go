package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var jwksLock sync.Mutex

func sanitizeToken(token string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9\-_\.]`)
	cleanToken := re.ReplaceAllString(token, "")
	return strings.TrimSpace(cleanToken)
}

func NewOidcClient(iss, id, secret string) (*OidcClient, error) {
	log.Printf("Calling NewOidcClient with iss: %s", iss)
	url := iss + ".well-known/openid-configuration"
	log.Printf("URL: %s", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{}
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

	log.Printf("Well-Known response body: %s", string(body))

	var result OidcClient
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse well-known response: %w", err)
	}

	if result.TokenEndpoint == "" || result.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("OIDC configuration is incomplete: %+v", result)
	}

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
