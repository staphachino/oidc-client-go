# OIDC Client (go)

Probably reinvented the wheel. Only god knows.

Uses the issuer provided to obtain the openid-configuration to perform Authorization, Exchange and Validation

## How to use

```
go get github.com/staphachino/oidc-client

oidc := NewOidcClient("https://auth.yoursite.org", "clientId", "clientSecret")
```


## Supported Grant Types

This library supports the following grant types:

```
    authorization_code
    refresh_token
    client_credentials
    password
    urn:ietf:params:oauth:grant-type:device_code
```

