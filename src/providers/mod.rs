use crate::{oidc::ValidationClaims, providers::github::GithubOidcClaims};
use serde::Deserialize;

pub mod github;

#[derive(Debug, Clone, Deserialize, Hash, PartialEq, Eq)]
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
