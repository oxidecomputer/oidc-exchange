// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{ApiDescription, ConfigDropshot, EndpointTagPolicy, HttpServerStarter, TagConfig};
use slog::Drain;
use std::{error::Error, net::SocketAddr};
use tracing_slog::TracingSlogDrain;

use crate::{context::Context, endpoints::exchange};

pub struct ServerConfig {
    pub context: Context,
    pub server_address: SocketAddr,
}

pub fn server(
    config: ServerConfig,
) -> Result<HttpServerStarter<Context>, Box<dyn Error + Send + Sync>> {
    let config_dropshot = ConfigDropshot {
        bind_address: config.server_address,
        default_request_body_max_bytes: 500 * 1024 * 1024,
        ..Default::default()
    };

    // Construct a shim to pipe dropshot logs into the global tracing logger
    let dropshot_logger = {
        let level_drain = slog::LevelFilter(TracingSlogDrain, slog::Level::Debug).fuse();
        let async_drain = slog_async::Async::new(level_drain).build().fuse();
        slog::Logger::root(async_drain, slog::o!())
    };

    let mut api = ApiDescription::new().tag_config(TagConfig {
        allow_other_tags: false,
        policy: EndpointTagPolicy::Any,
        tags: vec![].into_iter().collect(),
    });

    api.register(exchange).expect("Failed to register endpoint");

    HttpServerStarter::new(&config_dropshot, api, config.context, &dropshot_logger)
}
