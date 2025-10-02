use dropshot::{ApiDescription, ConfigDropshot, EndpointTagPolicy, HttpServerStarter, TagConfig};
use slog::Drain;
use std::{error::Error, net::SocketAddr};
use tracing_slog::TracingSlogDrain;

use crate::{context::Context, endpoints::exchange};
// use v_api::{inject_endpoints, v_system_endpoints};

// use crate::{
//     context::CassetteContext,
//     endpoints::{
//         forms::{
//             marketing::{
//                 submission::{marketing_remote_preview, marketing_remote_preview_cors},
//                 url::marketing_remote_preview_url,
//             },
//             tally::{
//                 preview_request_submission::tally_remote_preview,
//                 preview_request_url::tally_remote_preview_url,
//             },
//         },
//         images::{download_image, image_meta},
//         logs::{event_field, event_field_all, ingest, list_actors, list_events, list_requests},
//     },
//     permissions::CassettePermission,
// };

pub struct ServerConfig {
    pub context: Context,
    pub server_address: SocketAddr,
}

// v_system_endpoints!(CassetteContext, CassettePermission);

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
