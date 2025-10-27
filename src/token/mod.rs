// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde_json::Value;
use std::{
    any::{Any, TypeId},
    collections::HashMap,
    error::Error,
    fmt::Debug,
    hash::{BuildHasherDefault, Hasher},
};

use crate::settings::Name;

pub mod oxide;

// Based on the anymap implementation in the http crate
// https://docs.rs/http/1.3.1/src/http/extensions.rs.html#41-266
type NamedAnyMap =
    HashMap<TypeId, HashMap<Name, Box<dyn IntoAny + Send + Sync>>, BuildHasherDefault<IdHasher>>;
trait IntoAny {
    fn as_any(&self) -> &dyn Any;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

impl<T: Clone + Send + Sync + 'static> IntoAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[derive(Default)]
struct IdHasher(u64);

impl Hasher for IdHasher {
    fn write(&mut self, _: &[u8]) {
        unreachable!("TypeId calls write_u64");
    }

    #[inline]
    fn write_u64(&mut self, id: u64) {
        self.0 = id;
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

pub struct TokenClientStore {
    map: NamedAnyMap,
}

impl Debug for TokenClientStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenClientStore").finish()
    }
}

impl TokenClientStore {
    pub fn new() -> Self {
        Self {
            map: NamedAnyMap::default(),
        }
    }

    pub fn client<T: Send + Sync + 'static>(&self, name: &Name) -> Option<&T> {
        self.map
            .get(&TypeId::of::<T>())
            .and_then(|map| map.get(name))
            .and_then(|boxed| (**boxed).as_any().downcast_ref())
    }

    pub fn add_client<T: Clone + Send + Sync + 'static>(
        &mut self,
        name: Name,
        val: T,
    ) -> Option<T> {
        let entry = self
            .map
            .entry(TypeId::of::<T>())
            .or_insert_with(HashMap::default);

        entry
            .insert(name, Box::new(val))
            .and_then(|boxed| boxed.into_any().downcast().ok().map(|boxed| *boxed))
    }
}

pub trait GenerateToken {
    async fn generate_token(&self, token_store: &TokenClientStore)
    -> Result<Value, Box<dyn Error>>;
}
