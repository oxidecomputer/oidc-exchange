use bytes::Bytes;
use chrono::Utc;
use dropshot::{HttpError, HttpResponseOk, RequestContext, TypedBody, endpoint};
use futures_util::{Stream, StreamExt};
use oxide::ClientConsoleAuthExt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::pin::Pin;
use tap::TapFallible;

use crate::{
    CLIENT_ID,
    context::Context,
    oauth::{DeviceAccessTokenGrant, DeviceAuthorizationResponse},
};

// An Oxide access token with a fixed expiration time.
#[derive(Debug, Serialize, JsonSchema)]
pub struct OxideToken {
    access_token: String,
    expires_at: u32,
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
) -> Result<HttpResponseOk<OxideToken>, HttpError> {
    let ctx = rqctx.context();
    let token = body.into_inner().token;
    for provider in &ctx.providers {
        tracing::info!(
            issuer = provider.config.issuer,
            "Testing token against provider"
        );

        for authz in &provider.token_authorizations {
            tracing::info!(
                issuer = provider.config.issuer,
                host = authz.host.0,
                user = authz.user.0,
                "Testing if token matches authorization"
            );

            if let Ok(_) = provider
                .config
                .validate(&token, &authz.token)
                .tap_err(|err| {
                    tracing::info!(?err, "Failed to validate token");
                })
            {
                let expires_at = Utc::now().timestamp().max(0) as u32 + authz.duration;

                // The OIDC token matches a validation schema and we now need to construct a new
                // token to return back to the caller
                if let Some(sdk) = ctx.sdk_store.get(&(authz.host.clone(), authz.user.clone())) {
                    let data = sdk
                        .device_auth_request()
                        .body_map(|body| {
                            body.client_id(CLIENT_ID)
                                .ttl_seconds(if authz.duration == 0 {
                                    None
                                } else {
                                    Some(authz.duration.try_into().unwrap())
                                })
                        })
                        .send()
                        .await
                        .map_err(|err| {
                            tracing::error!(?err, "Failed to issue device auth request");
                            HttpError::for_internal_error("Failed to issue token".to_string())
                        })?
                        .into_inner()
                        .into_inner();
                    let device_response =
                        parse_bytestream::<DeviceAuthorizationResponse>(data).await?;

                    // Once we have the user code, submit it to the API to confirm the request
                    sdk.device_auth_confirm()
                        .body_map(|body| body.user_code(device_response.user_code))
                        .send()
                        .await
                        .map_err(|err| {
                            tracing::error!(?err, "Failed to confirm device auth request");
                            HttpError::for_internal_error("Failed to issue token".to_string())
                        })?;

                    // Given that we are performing these requests serially, the token should be
                    // ready by the time we make this call
                    let data = sdk
                        .device_access_token()
                        .body_map(|body| {
                            body.client_id(CLIENT_ID)
                                .device_code(device_response.device_code)
                                .grant_type("urn:ietf:params:oauth:grant-type:device_code")
                        })
                        .send()
                        .await
                        .map_err(|err| {
                            tracing::error!(?err, "Failed to retrieve device access token");
                            HttpError::for_internal_error("Failed to issue token".to_string())
                        })?
                        .into_inner()
                        .into_inner();
                    let access_token_response =
                        parse_bytestream::<DeviceAccessTokenGrant>(data).await?;

                    return Ok(HttpResponseOk(OxideToken {
                        access_token: access_token_response.access_token,
                        expires_at,
                    }));
                }
            }
        }
    }

    Err(HttpError::for_bad_request(
        Some("NO_MATCH".to_string()),
        "Token is not authorized for any resources".to_string(),
    ))
}

async fn parse_bytestream<T>(
    mut stream: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send + Sync>>,
) -> Result<T, HttpError>
where
    T: DeserializeOwned,
{
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        bytes.extend(
            chunk
                .map_err(|err| {
                    tracing::error!(?err, "Failed to read device auth response");
                    HttpError::for_internal_error("Failed to issue token".to_string())
                })?
                .to_vec(),
        );
    }

    Ok(serde_json::from_slice::<T>(&bytes).map_err(|err| {
        tracing::error!(?err, "Failed to parse device auth response");
        HttpError::for_internal_error("Failed to issue token".to_string())
    })?)
}
