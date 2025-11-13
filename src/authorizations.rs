// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::Deserialize;

use crate::oidc::ClaimValue;
use crate::token::github::GitHubTokenRequest;
use crate::token::oxide::OxideTokenRequest;
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct TokenClaims {
    pub issuer: String,
    pub claims: HashMap<String, ClaimValue>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct TokenAuthorization {
    pub authorization: TokenClaims,
    pub request: TokenStoreRequest,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "service", rename_all = "lowercase")]
pub enum TokenStoreRequest {
    Oxide(OxideTokenRequest),
    GitHub(GitHubTokenRequest),
}

#[derive(Debug, Deserialize)]
pub struct Authorizations {
    pub authorizations: Vec<TokenAuthorization>,
}
