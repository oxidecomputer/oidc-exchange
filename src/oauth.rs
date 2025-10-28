// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
}

#[derive(Debug, Deserialize)]
pub struct DeviceAccessTokenGrant {
    pub access_token: String,
}

#[derive(Debug, Deserialize, Error)]
#[error("Device access token acquisition failed with {error}")]
pub struct DeviceAccessTokenError {
    pub error: String,
    pub error_description: String,
}
