// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::endpoints::TokenRequest;
use crate::oidc::Claims;
use oso::{Class, Oso, OsoError, PolarClass, ToPolar};
use std::fmt::Display;
use std::path::Path;

pub struct Policy {
    oso: Oso,
}

impl Policy {
    pub fn new(path: &Path) -> Result<Self, OsoError> {
        let mut oso = Oso::new();
        oso.register_class(GitHubClass::get_polar_class())?;
        oso.register_class(OxideClass::get_polar_class())?;
        oso.register_class(create_utils_class())?;
        oso.load_files(vec![path])?;
        Ok(Self { oso })
    }

    pub fn ensure_allowed(
        &self,
        claims: &Claims,
        request: &TokenRequest,
    ) -> Result<(), PolicyError> {
        match request {
            TokenRequest::Oxide(oxide) => self.ensure_permutation(
                claims,
                OxideClass {
                    silo: oxide.silo.clone(),
                    duration: oxide.duration as _,
                },
            ),
            TokenRequest::GitHub(github) => {
                for repository in &github.repositories {
                    for permission in &github.permissions {
                        self.ensure_permutation(
                            claims,
                            GitHubClass {
                                repository: repository.clone(),
                                permission: permission.clone(),
                            },
                        )?;
                    }
                }
                Ok(())
            }
        }
    }

    fn ensure_permutation<T: ToPolar + Display>(
        &self,
        claims: &Claims,
        permutation: T,
    ) -> Result<(), PolicyError> {
        let string_repr = permutation.to_string();
        let mut result = self
            .oso
            .query_rule("allow_request", (claims.clone(), permutation))?;
        match result.next() {
            Some(Ok(_)) => Ok(()),
            Some(Err(e)) => Err(e.into()),
            None => Err(PolicyError::NotMatching(string_repr)),
        }
    }
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Policy")
    }
}

#[derive(PolarClass, Clone)]
#[polar(class_name = "Oxide")]
struct OxideClass {
    #[polar(attribute)]
    silo: String,
    #[polar(attribute)]
    duration: i64,
}

impl std::fmt::Display for OxideClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "silo {}", self.silo)
    }
}

#[derive(PolarClass, Clone)]
#[polar(class_name = "GitHub")]
struct GitHubClass {
    #[polar(attribute)]
    repository: String,
    #[polar(attribute)]
    permission: String,
}

impl std::fmt::Display for GitHubClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "permission {} on repository {}",
            self.permission, self.repository
        )
    }
}

pub(super) fn create_utils_class() -> Class {
    #[derive(Clone, PolarClass)]
    #[polar(class_name = "utils")]
    struct Utils;

    Utils::get_polar_class_builder()
        .add_class_method("concat", |a: String, b: String| format!("{a}{b}"))
        .build()
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("Failed to evaluate the authorization policy")]
    Oso(#[from] OsoError),
    #[error("{0} does not match the authorization policy")]
    NotMatching(String),
}
