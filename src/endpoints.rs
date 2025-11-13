// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{HttpError, HttpResponseOk, RequestContext, TypedBody, endpoint};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tap::TapFallible;

use crate::authorizations::TokenStoreService;
use crate::{context::Context, oidc::IssuerClaim};

// An Oxide access token with a fixed expiration time.
#[derive(Debug, Serialize, JsonSchema)]
pub struct Token {
    pub access_token: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExchangeBody {
    token: String,
}

/// Exchange an OIDC provider identity token for an Oxide access token.
#[endpoint {
    path = "/exchange",
    method = POST,
}]
pub async fn exchange(
    rqctx: RequestContext<Context>,
    body: TypedBody<ExchangeBody>,
) -> Result<HttpResponseOk<Token>, HttpError> {
    let ctx = rqctx.context();
    let token = body.into_inner().token;

    let issuer = jsonwebtoken::dangerous::insecure_decode::<IssuerClaim>(&token)
        .map_err(|err| {
            tracing::info!(?err, "Failed to decode token");
            HttpError::for_bad_request(None, "Invalid token".to_string())
        })?
        .claims
        .iss;

    let provider = ctx
        .providers
        .get(&issuer)
        .ok_or_else(|| {
            tracing::info!(issuer, "Provider not found for issuer");
            HttpError::for_bad_request(None, "Unsupported issuer".to_string())
        })?
        .clone();

    let authorizations = ctx
        .authorizations
        .get(&issuer)
        .iter()
        .map(|matches| matches.iter())
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    for authz in authorizations {
        tracing::info!(
            issuer = provider.read().unwrap().config.issuer,
            "Testing if token matches authorization"
        );

        // Continue to the next authorization if the token does not match the required constraints
        if provider
            .read()
            .unwrap()
            .config
            .validate(&ctx.settings, &token, &authz.authorization)
            .tap_err(|err| {
                tracing::info!(?err, "Failed to validate token");
            })
            .is_err()
        {
            continue;
        }

        let token = match &authz.request {
            TokenStoreService::Oxide(oxide) => {
                ctx.oxide_tokens.get(oxide).await.map_err(|err| {
                    tracing::error!(?err, "Failed to generate token");
                    HttpError::for_internal_error("Failed to generate token".to_string())
                })?
            }
            TokenStoreService::GitHub(github) => {
                ctx.github_tokens.get(github).await.map_err(|err| {
                    tracing::error!(?err, "Failed to generate token");
                    if err.safe_to_expose() {
                        HttpError::for_bad_request(None, format!("Failed to generate token: {err}"))
                    } else {
                        HttpError::for_internal_error("Failed to generate token".to_string())
                    }
                })?
            }
        };

        return Ok(HttpResponseOk(token));
    }

    Err(HttpError::for_bad_request(
        Some("NO_MATCH".to_string()),
        "Token is not authorized for any resources".to_string(),
    ))
}
