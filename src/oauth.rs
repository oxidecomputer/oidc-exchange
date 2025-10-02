use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
}

#[derive(Debug, Deserialize)]
pub struct DeviceAccessTokenGrant {
    pub access_token: String,
}
