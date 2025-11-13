# Oxide OIDC Token Exchanger

A very tiny server that exchanges OIDC identity tokens for tokens from (an eventual)
number of other services.

The server exposes a single endpoint at `/exchange` that accepts a POST request with
an OIDC identity token and returns an access token for an external service based on
configured service rules.

## Usage

Providers are installed into the server via the `providers` setting. This should be
defined via urls to the provider's OpenID configuration url.

```toml
# Adding GitHub as an OIDC provider
[[providers]]
url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
```

Adding a provider does not grant any access by default. It only enables the server to
discover their OIDC settings, and access the key sets that they provide for validating
identity tokens.

To be able to issue access tokens, service-specific configuration needs to be present in
the settings file:

* For Oxide tokens, a map of silo URLs to access tokens needs to be provided:

  ```toml
  [oxide_silos]
  "https://oxide.sys.r3.oxide-preview.com" = "oxide-token-helloworld"
  "https://corp-prod.sys.r3.oxide-preview.com" = "oxide-token-supersecure"
  ```

To grant authorization for an identity token to be exchanged for an access token, an
authorization mapping of the token claims to token request settings must be defined.
This is the glue between the provider and the token store. To connect these two, a
token authorization defines specific claims that must be present in the identity token
in order to be authorized to exchange it for an access token. The issuer and audience
claims are required for all authorizations, but it is strongly recommended to define
additional claims to narrow down which identity tokens are authorized.

```toml
# Sample configuration to authorize identity tokens from GitHub Actions running in
# the oxidecomputer/oidc-exchange repository on the main branch.
[authorizations.authorization]
issuer = "https://token.actions.githubusercontent.com"
audience = "https://github.com/octo-org"
claims = { repository = "oxidecomputer/oidc-exchange", ref = "refs/head/main" }
```

With the mapping in place the final configuration required is the token settings for the
exchange service. These will be different per service. Currently the only supported
service is the Oxide rack, and its settings are quite simple.

```toml
[authorizations.request]
# Indicator of the service this request is for, in this case an Oxide rack (required).
service = "oxide"
# URL of the silo to create a token for, must be present in [oxide_silos] (required).
silo = "https://oxide.sys.r3.oxide-preview.com"
# The duration that the access token should be valid for (required).
duration = 3600
```
