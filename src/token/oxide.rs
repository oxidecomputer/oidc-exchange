// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use oxide::{ByteStream, ClientConsoleAuthExt};
use serde::Deserialize;
use std::error::Error as StdError;
use tap::TapFallible;
use thiserror::Error;

use crate::{
    endpoints::Token,
    oauth::{DeviceAccessTokenError, DeviceAccessTokenGrant, DeviceAuthorizationResponse},
    settings::Name,
    token::{GenerateToken, TokenClientStore},
    util::{ByteStreamError, parse_bytestream},
};

static CLIENT_ID: &str = "730ae5f1-a728-4a5d-9a06-cf09b653cca6";

#[derive(Debug, Error)]
pub enum OxideError {
    #[error("Error reading response")]
    ByteStream(#[from] ByteStreamError),
    #[error("Failed to issue device access token request")]
    DeviceAuthRequest(#[from] DeviceAccessTokenError),
    #[error("No client for the requested service and name exists")]
    MissingClient,
    #[error("Remote service error")]
    Oxide(#[from] oxide::Error<oxide::types::Error>),
    #[error("Remote service error")]
    OxideByteError(#[from] oxide::Error<ByteStream>),
}

#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq)]
pub struct OxideTokenStoreRequest {
    pub store: Name,
    pub duration: u32,
}

impl GenerateToken for OxideTokenStoreRequest {
    async fn generate_token(
        &self,
        client_store: &TokenClientStore,
    ) -> Result<Token, Box<dyn StdError>> {
        let client = client_store
            .client::<oxide::Client>(&self.store)
            .ok_or(OxideError::MissingClient)?;

        let device_response = match client
            .device_auth_request()
            .body_map(|body| {
                body.client_id(CLIENT_ID)
                    .ttl_seconds(if self.duration == 0 {
                        None
                    } else {
                        Some(self.duration.try_into().unwrap())
                    })
            })
            .send()
            .await
        {
            Ok(data) => {
                parse_bytestream::<DeviceAuthorizationResponse>(data.into_inner().into_inner())
                    .await?
            }
            Err(err) => {
                tracing::error!(?err, "Failed to issue device auth request");

                // Attempt to parse the error response
                match err {
                    oxide::Error::ErrorResponse(stream) => {
                        let error_data =
                            parse_bytestream::<DeviceAccessTokenError>(stream.into_inner_stream())
                                .await?;
                        return Err(error_data.into());
                    }
                    _ => return Err(err.into()),
                }
            }
        };

        // Once we have the user code, submit it to the API to confirm the request
        client
            .device_auth_confirm()
            .body_map(|body| body.user_code(device_response.user_code))
            .send()
            .await
            .tap_err(|err| {
                tracing::error!(?err, "Failed to confirm device auth request");
            })?;

        // Given that we are performing these requests serially, the token should be
        // ready by the time we make this call
        let data = client
            .device_access_token()
            .body_map(|body| {
                body.client_id(CLIENT_ID)
                    .device_code(device_response.device_code)
                    .grant_type("urn:ietf:params:oauth:grant-type:device_code")
            })
            .send()
            .await
            .tap_err(|err| {
                tracing::error!(?err, "Failed to retrieve device access token");
            })?
            .into_inner()
            .into_inner();
        let access_token_response = parse_bytestream::<DeviceAccessTokenGrant>(data).await?;

        Ok(Token {
            access_token: access_token_response.access_token,
        })
    }
}
