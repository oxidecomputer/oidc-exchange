// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::endpoints::Token;
use crate::settings::Settings;
use jsonwebtoken::{Algorithm, EncodingKey};
use reqwest::{Client, RequestBuilder, StatusCode};
use schemars::JsonSchema;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

static USER_AGENT: &str = "https://github.com/oxidecomputer/oidc-exchange";

#[derive(Clone, Debug, Deserialize, JsonSchema, Hash, PartialEq, Eq)]
pub struct GitHubTokenRequest {
    pub repositories: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug)]
struct State {
    client: Client,
    client_id: String,
    private_key: EncodingKey,
}

#[derive(Debug)]
pub struct GitHubTokens {
    state: Option<State>,
}

impl GitHubTokens {
    pub fn new(settings: &Settings) -> Result<Self, GitHubTokenError> {
        if let Some(settings) = &settings.github {
            let private_key = std::fs::read(&settings.private_key_path).map_err(|e| {
                GitHubTokenError::ReadPrivateKey(settings.private_key_path.clone(), e)
            })?;
            Ok(GitHubTokens {
                state: Some(State {
                    client: Client::new(),
                    client_id: settings.client_id.clone(),
                    private_key: EncodingKey::from_rsa_pem(&private_key)
                        .map_err(GitHubTokenError::LoadPrivateKey)?,
                }),
            })
        } else {
            Ok(GitHubTokens { state: None })
        }
    }

    pub async fn get(&self, request: &GitHubTokenRequest) -> Result<Token, GitHubTokenError> {
        let state = self.state.as_ref().ok_or(GitHubTokenError::NoCredentials)?;

        // Generate a JWT valid for 5 minutes, used to authenticate with GitHub.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("we time travelled earlier than 1970, go collect your Nobel prize")
            .as_secs();
        let jwt = jsonwebtoken::encode(
            &jsonwebtoken::Header {
                alg: Algorithm::RS256,
                ..Default::default()
            },
            &serde_json::json!({
                "iss": state.client_id,
                "iat": now - 10, // Handle skewed clocks.
                "exp": now + 300,
            }),
            &state.private_key,
        )
        .map_err(GitHubTokenError::EncodeJwt)?;

        // We need all repositories to belong to a single namespace (user or organization), as we
        // need to assume the role of the installation of the app in that namespace. While we are
        // at it, we also collect the repository names without the namespace, as the API requires.
        let mut found_namespace = None;
        let mut repos_without_namespace = Vec::new();
        for repo in &request.repositories {
            match repo.split_once('/') {
                Some((namespace, name)) if !name.contains('/') => {
                    if found_namespace.is_some() && found_namespace != Some(namespace) {
                        return Err(GitHubTokenError::DifferentOrgs);
                    }
                    found_namespace = Some(namespace);
                    repos_without_namespace.push(name);
                }
                _ => return Err(GitHubTokenError::NotAGitHubRepository(repo.clone())),
            }
        }
        let namespace = found_namespace.ok_or(GitHubTokenError::NoRepositories)?;

        // Convert the permission:level syntax in the format GitHub expects.
        let mut permissions = HashMap::new();
        for permission in &request.permissions {
            match permission.split_once(':') {
                Some((name, level)) if !name.contains('/') => {
                    if let Some(_) = permissions.insert(name, level) {
                        return Err(GitHubTokenError::DuplicatePermission(name.into()));
                    }
                }
                _ => return Err(GitHubTokenError::NotAPermission(permission.into())),
            }
        }

        // Get the installation ID. We look for the namespace in both the users and the
        // organizations, to gracefully handle when the app is installed on a personal account
        // rather than an organization.
        let mut found_installation = None;
        for kind in ["orgs", "users"] {
            let response = github_request::<InstallationResponse>(
                state
                    .client
                    .get(format!(
                        "https://api.github.com/{kind}/{namespace}/installation"
                    ))
                    .bearer_auth(&jwt),
            )
            .await;
            match response {
                Ok(response) => found_installation = Some(response.id),
                Err(GitHubTokenError::GitHubError(_, StatusCode::NOT_FOUND, _)) => continue,
                Err(err) => return Err(err),
            }
        }
        let installation = found_installation
            .ok_or_else(|| GitHubTokenError::AppNotInstalled(namespace.into()))?;

        // Request the access token from GitHub.
        let access_token: AccessTokenResponse = github_request(
            state
                .client
                .post(format!(
                    "https://api.github.com/app/installations/{installation}/access_tokens"
                ))
                .bearer_auth(&jwt)
                .json(&serde_json::json!({
                    "repositories": repos_without_namespace,
                    "permissions": permissions,
                })),
        )
        .await?;

        Ok(Token {
            access_token: access_token.token,
        })
    }
}

#[derive(serde::Deserialize)]
struct InstallationResponse {
    id: u64,
}

#[derive(serde::Deserialize)]
struct AccessTokenResponse {
    token: String,
}

async fn github_request<T>(request: RequestBuilder) -> Result<T, GitHubTokenError>
where
    T: DeserializeOwned,
{
    #[derive(serde::Deserialize)]
    struct GitHubError {
        message: String,
    }

    let response = request
        .header("user-agent", USER_AGENT)
        .send()
        .await
        .map_err(GitHubTokenError::Http)?;
    let status = response.status();

    if status.is_success() {
        response.json().await.map_err(GitHubTokenError::Http)
    } else {
        let url = response.url().to_string();
        let text = response.text().await.map_err(GitHubTokenError::Http)?;
        // GitHub usually sends error responses as JSON, but if there is an upstream error with
        // GitHub non-JSON might be returned. Gracefully handle that.
        match serde_json::from_str(&text) {
            Ok(GitHubError { message }) => Err(GitHubTokenError::GitHubError(url, status, message)),
            Err(_) => Err(GitHubTokenError::GitHubError(url, status, text)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GitHubTokenError {
    #[error("GitHub credentials are not configured for this instance of oidc-exchange")]
    NoCredentials,
    #[error("failed to read the GitHub App private key located at {}", .0.display())]
    ReadPrivateKey(PathBuf, #[source] std::io::Error),
    #[error("Failed to load the GitHub App private key")]
    LoadPrivateKey(#[source] jsonwebtoken::errors::Error),
    #[error("Failed to encode the JWT")]
    EncodeJwt(#[source] jsonwebtoken::errors::Error),
    #[error("Repository name {0} is not in the `org/name` format")]
    NotAGitHubRepository(String),
    #[error("The repositories requested for this token belong to different organizations")]
    DifferentOrgs,
    #[error("The requested token asked for access to no repositories")]
    NoRepositories,
    #[error("HTTP error")]
    Http(#[source] reqwest::Error),
    #[error("Request to {0} failed with status {1}: {2}")]
    GitHubError(String, StatusCode, String),
    #[error("The permission {0} is requested multiple times")]
    DuplicatePermission(String),
    #[error("The permission string {0} is not a valid permission")]
    NotAPermission(String),
    #[error("oidc-exchange's GitHub App is not installed on {0}")]
    AppNotInstalled(String),
}

impl GitHubTokenError {
    pub fn safe_to_expose(&self) -> bool {
        match self {
            GitHubTokenError::ReadPrivateKey(..)
            | GitHubTokenError::LoadPrivateKey(..)
            | GitHubTokenError::EncodeJwt(..)
            | GitHubTokenError::Http(..) => false,
            GitHubTokenError::NoCredentials
            | GitHubTokenError::NotAGitHubRepository(..)
            | GitHubTokenError::DifferentOrgs
            | GitHubTokenError::NoRepositories
            | GitHubTokenError::DuplicatePermission(..)
            | GitHubTokenError::GitHubError(..)
            | GitHubTokenError::AppNotInstalled(..)
            | GitHubTokenError::NotAPermission(..) => true,
        }
    }
}
