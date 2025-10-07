// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{oidc::ValidationClaims, providers::github::GithubOidcClaims};
use serde::Deserialize;

pub mod github;

#[derive(Debug, Clone, Deserialize, Hash, PartialEq, Eq)]
#[serde(untagged)]
pub enum Claims {
    #[serde(rename = "github")]
    GitHub(GithubOidcClaims),
}

impl ValidationClaims for Claims {
    fn validate(&self, claims: &Self) -> bool {
        match self {
            Claims::GitHub(github_claims) => github_claims.validate(claims),
        }
    }
}
