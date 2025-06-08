# OidcClient – Go OpenID Connect Client

A full-featured OpenID Connect (OIDC) client for Go, supporting multiple OAuth2 grant types, token validation, introspection, revocation, JWKS-based verification, and device flow.

## Features

* Password grant, client credentials, authorization code, refresh token, and device code flow support
* JWT validation with RS256/ES256 using JWKS
* Token introspection and revocation
* Userinfo and logout endpoint integration
* Token persistence (load/save to file)
* Pluggable scopes, algorithms, and grant types
* Token sanitization and secure logging
* Token refresh support

## Getting Started

### Create and Configure the Client

```go
client := &oidc.OidcClient{
    clientId:     "your-client-id",
    clientSecret: "your-client-secret",
    TokenEndpoint: "https://your-idp.com/oauth/token",
    AuthorizationEndpoint: "https://your-idp.com/oauth/authorize",
    UserinfoEndpoint: "https://your-idp.com/oauth/userinfo",
    IntrospectionEndpoint: "https://your-idp.com/oauth/introspect",
    RevocationEndpoint: "https://your-idp.com/oauth/revoke",
    JwksUri:      "https://your-idp.com/.well-known/jwks.json",
    httpClient:   &http.Client{Timeout: 10 * time.Second},
}
```

or to generate this based on the openid-configuration that should be accompling with your identity provider

```go
client := NewOidcClient("https://your-idp.com/", "your-client-id", "your-client-secret")
```


### Set Scopes

```go
err := SetScopes([]string{"openid", "profile", "email"})
```

or to fail with a panic:

```go
client.MustSetScopes([]string{"openid", "profile", "email"})
```

### Perform Token Exchange

#### Password Grant

```go
token, err := client.Exchange("password", "user@example.com", "your-password")
```

#### Device Code Grant

```go
token, err := client.Exchange("urn:ietf:params:oauth:grant-type:device_code", "", "")
```

#### Refresh Token Grant

```go
token, err := client.Exchange("refresh_token", existingRefreshToken, "")
```

#### Authorization Code Grant

```go
client.Authorize() // Launches a local web server and waits for a callback
```

## Validate or Introspect Tokens

### Validate JWT Token via JWKS

```go
claims, err := client.Validate(token.AccessToken)
```

### Introspect Token via Introspection Endpoint

```go
claims, err := client.Introspect(token.AccessToken)
```

## Refresh and Save Tokens

### Load from File

```go
err := client.LoadTokenFromFile("token.json")
```

### Save to File

```go
err := client.SaveTokenToFile("token.json")
```

## End Session and Logout

```go
err := client.EndSession(token.IDToken, "https://your-app.com/post-logout")
```

## Get Userinfo

```go
userinfo, err := client.UserInfo(token.AccessToken)
```

## Revoke Token

```go
err := client.Revoke(token.AccessToken, "access_token")
err := client.Revoke(token.RefreshToken, "refresh_token")

```

## Types

* `OidcClient` – Core client object
* `OidcToken` – Struct holding `access_token`, `refresh_token`, `id_token`, and expiry
* `OidcDeviceCode` – Device flow metadata
* `JWK` – JSON Web Key structure for validating JWTs

## Supported Algorithms

* RSA (`RS256`, etc.)
* EC (`ES256`, etc.)

## Notes

* The client uses a local HTTP server to receive the callback during the authorization code flow.
* JWT validation is performed using keys from the configured `jwks_uri`.
* Device flow polling handles `authorization_pending`, `slow_down`, and token retrieval.
