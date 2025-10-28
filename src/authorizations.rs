// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::Deserialize;

use crate::{
    providers::Claims,
    settings::Name,
    token::{GenerateToken, oxide::OxideTokenStoreRequest},
};

#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq)]
pub struct TokenClaims {
    pub issuer: String,
    pub audience: String,
    pub claims: Claims,
}

#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq)]
pub struct TokenAuthorization {
    pub authorization: TokenClaims,
    pub request: TokenStoreRequest,
}

#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq)]
pub struct TokenStoreRequest {
    pub name: Name,
    #[serde(flatten)]
    pub service: TokenStoreService,
}

#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq)]
#[serde(tag = "service", rename_all = "lowercase")]
pub enum TokenStoreService {
    Oxide(OxideTokenStoreRequest),
}

impl GenerateToken for TokenStoreService {
    async fn generate_token(
        &self,
        token_store: &crate::token::TokenClientStore,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        match self {
            Self::Oxide(store) => store.generate_token(token_store).await,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Authorizations {
    pub authorizations: Vec<TokenAuthorization>,
}
