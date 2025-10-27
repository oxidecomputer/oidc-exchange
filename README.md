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
provider = { url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration" }
```

Adding a provider does not grant any access by default. It only enables the server to
discover their OIDC settings, and access the key sets that they provide for validating
identity tokens.

To be able to issue access tokens, each service needs to have one (or more) token token
stores configured. These internal clients that will be connecting to external services
and generating access tokens for them. As an example, configuring a token store for The
Oxide rack looks like:

```toml
[[token_store]]
name = "oxide-rack1"
host = "https://silo.sys.rack1.oxide.computer"
token = "secret_token"
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
audience = "https://github.com/octo-org",
claims = { repository = "oxidecomputer/oidc-exchange", ref = "refs/head/main" }
```

With the mapping in place the final configuration required is the token settings for the
exchange service. These will be different per service. Currently the only supported
service is the Oxide rack, and its settings are quite simple.

```toml
[authorizations.request]
# The name of the token store to use for the request. (Defined above)
store = "oxide-rack1"
# Indicator of the service this request is for. Currently only "oxide" is supported.
service = "oxide"

# Oxide specific settings for the request.

# The duration that the access token should be valid for.
duration = 3600
```
