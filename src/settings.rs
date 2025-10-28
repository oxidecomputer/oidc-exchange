// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use config::{Config, ConfigError, File};
use oxide::{Client as OxideSdk, ClientConfig};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::error::Error as StdError;

use crate::{oidc::OidcProvider, token::TokenClientStore};

#[derive(Debug, Clone, Deserialize, Hash, PartialEq, Eq)]
pub struct Name(pub String);

#[derive(Debug, Clone, Deserialize, Hash, PartialEq, Eq)]
pub struct Host(pub String);

#[derive(Debug, Deserialize)]
#[serde(tag = "service")]
pub enum TokenStoreConfig {
    Oxide(OxideTokenStoreConfig),
}

#[derive(Debug, Deserialize)]
pub struct OxideTokenStoreConfig {
    name: Name,
    host: Host,
    token: SecretString,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub tokens_config: String,
    pub log_directory: Option<String>,
    pub port: Option<u16>,
    pub providers: Vec<OidcProvider>,
    #[serde(default)]
    pub token_store: Vec<TokenStoreConfig>,
}

impl Settings {
    pub fn new(config_sources: Option<Vec<String>>) -> Result<Self, ConfigError> {
        let mut config =
            Config::builder().add_source(File::with_name("settings.toml").required(false));

        for source in config_sources.unwrap_or_default() {
            config = config.add_source(File::with_name(&source).required(false));
        }

        config.build()?.try_deserialize()
    }
}

impl TokenStoreConfig {
    pub fn name(&self) -> &Name {
        match self {
            TokenStoreConfig::Oxide(OxideTokenStoreConfig { name, .. }) => name,
        }
    }

    pub fn add_to_store(
        self,
        store: &mut TokenClientStore,
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
        match self {
            TokenStoreConfig::Oxide(OxideTokenStoreConfig { name, host, token }) => {
                let config =
                    ClientConfig::default().with_host_and_token(&host.0, token.expose_secret());
                store.add_client(name, OxideSdk::new_authenticated_config(&config)?);
            }
        }

        Ok(())
    }
}
