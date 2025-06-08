package oidc

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func (t *OidcToken) IsExpired() bool {
	if t == nil || t.ExpiresIn == 0 {
		return false
	}
	return time.Since(t.ObtainedAt) > time.Duration(t.ExpiresIn)*time.Second
}

func (t *OidcToken) SaveToFile(path string) error {
	if t == nil {
		return fmt.Errorf("cannot save a nil token")
	}
	t.ObtainedAt = time.Now()

	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}
