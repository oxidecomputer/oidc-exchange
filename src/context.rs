// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    collections::HashMap,
    error::Error as StdError,
    sync::{Arc, RwLock},
};
use thiserror::Error;

use crate::{
    oidc::{OidcError, ResolvedOidcConfig},
    policy::Policy,
    settings::Settings,
    token::{
        github::{GitHubTokenError, GitHubTokens},
        oxide::{OxideError, OxideTokens},
    },
};
use oso::OsoError;

#[derive(Debug, Error)]
pub enum ContextBuildError {
    #[error("Failed to construct client")]
    ClientConstruction(Box<dyn StdError + Send + Sync>),
    #[error("Failed to initialize the Oxide token store")]
    OxideTokens(#[from] OxideError),
    #[error("Failed to initialize the GitHub token store")]
    GitHubTokens(#[from] GitHubTokenError),
    #[error("Encountered an error configuring OIDC providers")]
    Oidc(#[from] OidcError),
    #[error("Failed to initialize the Oso policy")]
    Oso(#[from] OsoError),
}

#[derive(Debug)]
pub struct ResolvedOidcProvider {
    pub config: ResolvedOidcConfig,
}

#[derive(Debug)]
pub struct Context {
    pub settings: Settings,
    pub providers: HashMap<String, Arc<RwLock<ResolvedOidcProvider>>>,
    pub oxide_tokens: OxideTokens,
    pub github_tokens: GitHubTokens,
    pub policy: Policy,
}

impl Context {
    pub async fn new(settings: Settings) -> Result<Self, ContextBuildError> {
        let client = reqwest::Client::new();

        let mut providers = HashMap::new();
        for provider in &settings.providers {
            let resolved = ResolvedOidcProvider {
                config: provider
                    .fetch_config(&client)
                    .await?
                    .resolve(&client)
                    .await?,
            };
            let issuer = resolved.config.issuer.clone();
            providers.insert(issuer, Arc::new(RwLock::new(resolved)));
        }

        Ok(Context {
            providers,
            oxide_tokens: OxideTokens::new(&settings)?,
            github_tokens: GitHubTokens::new(&settings)?,
            policy: Policy::new(&settings.policy_path)?,
            settings,
        })
    }
}
