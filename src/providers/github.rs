// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::Deserialize;

use crate::{oidc::ValidationClaims, providers::Claims};

#[derive(Debug, Clone, Deserialize, Hash, PartialEq, Eq)]
pub struct GithubOidcClaims {
    jti: Option<String>,
    sub: Option<String>,
    aud: Option<String>,
    #[serde(rename = "ref")]
    ref_: Option<String>,
    repository: Option<String>,
    repository_owner: Option<String>,
    actor_id: Option<String>,
    repository_id: Option<String>,
    repository_owner_id: Option<String>,
    actor: Option<String>,
    workflow: Option<String>,
    head_ref: Option<String>,
    base_ref: Option<String>,
    event_name: Option<String>,
    ref_type: Option<String>,
    job_workflow_ref: Option<String>,
    iss: Option<String>,
}

impl ValidationClaims for GithubOidcClaims {
    fn validate(&self, claims: &Claims) -> bool {
        match claims {
            Claims::GitHub(claims) => {
                check_claim(self.jti.as_deref(), claims.jti.as_deref())
                    && check_claim(self.sub.as_deref(), claims.sub.as_deref())
                    && check_claim(self.aud.as_deref(), claims.aud.as_deref())
                    && check_claim(self.ref_.as_deref(), claims.ref_.as_deref())
                    && check_claim(self.repository.as_deref(), claims.repository.as_deref())
                    && check_claim(
                        self.repository_owner.as_deref(),
                        claims.repository_owner.as_deref(),
                    )
                    && check_claim(self.actor_id.as_deref(), claims.actor_id.as_deref())
                    && check_claim(
                        self.repository_id.as_deref(),
                        claims.repository_id.as_deref(),
                    )
                    && check_claim(
                        self.repository_owner_id.as_deref(),
                        claims.repository_owner_id.as_deref(),
                    )
                    && check_claim(self.actor.as_deref(), claims.actor.as_deref())
                    && check_claim(self.workflow.as_deref(), claims.workflow.as_deref())
                    && check_claim(self.head_ref.as_deref(), claims.head_ref.as_deref())
                    && check_claim(self.base_ref.as_deref(), claims.base_ref.as_deref())
                    && check_claim(self.event_name.as_deref(), claims.event_name.as_deref())
                    && check_claim(self.ref_type.as_deref(), claims.ref_type.as_deref())
                    && check_claim(
                        self.job_workflow_ref.as_deref(),
                        claims.job_workflow_ref.as_deref(),
                    )
                    && check_claim(self.iss.as_deref(), claims.iss.as_deref())
            }
        }
    }
}

fn check_claim(a: Option<&str>, b: Option<&str>) -> bool {
    a.and_then(|required| b.map(|supplied| required == supplied).or(Some(false)))
        .unwrap_or(true)
}
