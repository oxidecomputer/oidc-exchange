use config::{Config, ConfigError, File};
use secrecy::SecretString;
use serde::Deserialize;
use std::collections::HashMap;

use crate::{oidc::OidcProvider, providers::Claims};

#[derive(Debug, Clone, Deserialize, Hash, PartialEq, Eq)]
pub struct Host(pub String);

#[derive(Debug, Clone, Deserialize, Hash, PartialEq, Eq)]
pub struct User(pub String);

#[derive(Debug, Deserialize, Hash, PartialEq, Eq)]
pub struct TokenAuthorization {
    pub claims: Claims,
    pub host: Host,
    pub user: User,
    pub duration: u32,
}

#[derive(Debug, Deserialize)]
pub struct OidcProviderConfiguration {
    pub provider: OidcProvider,
    #[serde(default)]
    pub token_authorizations: Vec<TokenAuthorization>,
}

#[derive(Debug, Deserialize)]
pub struct TokenStoreEntry {
    pub host: Host,
    pub user: User,
    pub token: SecretString,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub log_directory: Option<String>,
    pub port: Option<u16>,
    pub providers: Vec<OidcProviderConfiguration>,
    #[serde(default)]
    pub token_store: Vec<TokenStoreEntry>,
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
