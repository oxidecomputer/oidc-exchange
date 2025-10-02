# Oxide OIDC Token Exchanger

A very tiny server that exchanges OIDC identity tokens for Oxide API access tokens.

The server exposes a single endpoint at `/exchange` that accepts a POST request with
an OIDC identity token and returns an access token for the Oxide API based on
pre-approved claim mappings.

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

To grant authorization for an identity token to be exchanged for an access token, an
authorization mapping of the token claims to token request settings must be defined.

Here we authorize validated tokens with specific `repository` and `ref` claims to be
exchanged for access token on behalf of the `user@oxidecomputer.com` user in the
`demo.sys.rack.company.tld` silo. The duration field constrains the lifetime of the
token so that it expires one hour after it is issued.

```toml
[[providers.token_authorizations]]
host = "https://demo.sys.rack.company.tld"
user = "user@oxidecomputer.com"
duration = 3600
claims = { github = { repository = "company-organization/repo", ref = "refs/head/main" } }
```

Currently the only way to provision new access tokens for the Oxide API is to have
either a valid access token or a valid session key. In the exchangers case it requires that
every user for which an authorization mapping exists, a root token is configured. This
token is used to generate new access tokens for callers.

```toml
[[token_store]]
host = "https://demo.sys.rack.company.tld"
user = "user@oxidecomputer.com"
token = "secret_token"
```
