// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::Deserialize;

use crate::{providers::Claims, token::oxide::OxideTokenRequest};

#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq)]
pub struct TokenClaims {
    pub issuer: String,
    pub audience: String,
    pub claims: Claims,
}

#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq)]
pub struct TokenAuthorization {
    pub authorization: TokenClaims,
    pub request: TokenStoreService,
}

#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq)]
#[serde(tag = "service", rename_all = "lowercase")]
pub enum TokenStoreService {
    Oxide(OxideTokenRequest),
}

#[derive(Debug, Deserialize)]
pub struct Authorizations {
    pub authorizations: Vec<TokenAuthorization>,
}
