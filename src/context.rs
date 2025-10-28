// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use oxide::OxideAuthError;
use std::{
    collections::HashMap,
    error::Error as StdError,
    sync::{Arc, RwLock},
};
use thiserror::Error;

use crate::{
    authorizations::{Authorizations, TokenAuthorization},
    oidc::{OidcError, ResolvedOidcConfig},
    settings::Settings,
    token::TokenClientStore,
};

#[derive(Debug, Error)]
pub enum ContextBuildError {
    #[error("Failed to construct client")]
    ClientConstruction(Box<dyn StdError + Send + Sync>),
    #[error("Failed to create an Oxide SDK client")]
    FailedToCreateSdk(#[from] OxideAuthError),
    #[error("Encountered an error configuring OIDC providers")]
    Oidc(#[from] OidcError),
}

#[derive(Debug)]
pub struct ResolvedOidcProvider {
    pub config: ResolvedOidcConfig,
}

#[derive(Debug)]
pub struct Context {
    pub providers: HashMap<String, Arc<RwLock<ResolvedOidcProvider>>>,
    pub authorizations: HashMap<String, Vec<TokenAuthorization>>,
    pub clients: TokenClientStore,
}

impl Context {
    pub async fn new(settings: Settings, auths: Authorizations) -> Result<Self, ContextBuildError> {
        let client = reqwest::Client::new();

        let mut providers = HashMap::new();
        for provider in settings.providers {
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

        let mut authorizations: HashMap<String, Vec<TokenAuthorization>> = HashMap::new();
        for authorization in auths.authorizations {
            let entry = authorizations.entry(authorization.authorization.issuer.clone());
            entry.or_default().push(authorization);
        }

        let mut clients = TokenClientStore::new();
        for store_config in settings.token_store {
            store_config
                .add_to_store(&mut clients)
                .map_err(ContextBuildError::ClientConstruction)?;
        }

        Ok(Context {
            providers,
            authorizations,
            clients,
        })
    }
}
