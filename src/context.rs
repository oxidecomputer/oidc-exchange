use oxide::{Client as OxideSdk, ClientConfig, OxideAuthError};
use secrecy::ExposeSecret;
use std::collections::HashMap;
use thiserror::Error;

use crate::{
    oidc::{OidcError, ResolvedOidcConfig},
    settings::{Host, Settings, TokenAuthorization, TokenStoreEntry, User},
};

#[derive(Debug, Error)]
pub enum ContextBuildError {
    #[error("Failed to create an Oxide SDK client")]
    FailedToCreateSdk(#[from] OxideAuthError),
    #[error("Encountered an error configuring OIDC providers")]
    Oidc(#[from] OidcError),
}

#[derive(Debug)]
pub struct ResolvedOidcProvider {
    pub config: ResolvedOidcConfig,
    pub token_authorizations: Vec<TokenAuthorization>,
}

#[derive(Debug)]
pub struct Context {
    pub providers: Vec<ResolvedOidcProvider>,
    pub sdk_store: HashMap<(Host, User), OxideSdk>,
}

impl Context {
    pub async fn new(settings: Settings) -> Result<Self, ContextBuildError> {
        let client = reqwest::Client::new();

        let mut providers = vec![];
        for provider in settings.providers {
            providers.push(ResolvedOidcProvider {
                config: provider
                    .provider
                    .fetch_config(&client)
                    .await?
                    .resolve(&client)
                    .await?,
                token_authorizations: provider.token_authorizations,
            });
        }

        let mut sdk_store = HashMap::new();
        for TokenStoreEntry { host, user, token } in settings.token_store {
            let config =
                ClientConfig::default().with_host_and_token(&host.0, token.expose_secret());
            sdk_store.insert((host, user), OxideSdk::new_authenticated_config(&config)?);
        }

        Ok(Context {
            providers,
            sdk_store,
        })
    }
}
