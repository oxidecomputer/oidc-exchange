// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde::de::DeserializeOwned;
use std::pin::Pin;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ByteStreamError {
    #[error("Failed to read bytes from stream")]
    FailedToRead,
    #[error("Failed to parse read bytes")]
    FailedToParse,
}

pub async fn parse_bytestream<T>(
    mut stream: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send + Sync>>,
) -> Result<T, ByteStreamError>
where
    T: DeserializeOwned,
{
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        bytes.extend(
            chunk
                .map_err(|err| {
                    tracing::error!(?err, "Failed to read byte stream");
                    ByteStreamError::FailedToRead
                })?
                .to_vec(),
        );
    }

    Ok(serde_json::from_slice::<T>(&bytes).map_err(|err| {
        tracing::error!(?err, "Failed to parse byte stream");
        ByteStreamError::FailedToParse
    })?)
}
