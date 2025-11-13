// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;

use config::{Config, ConfigError, File};
use secrecy::SecretString;
use serde::Deserialize;

use crate::oidc::OidcProvider;

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub tokens_config: String,
    pub log_directory: Option<String>,
    pub port: Option<u16>,
    pub providers: Vec<OidcProvider>,
    #[serde(default)]
    pub oxide_silos: HashMap<String, SecretString>,
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
