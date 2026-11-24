//! Management API on `api_host`: bearer admin token, JSON, OpenAPI via utoipa.
//!
//! The axum router is built once; each request runs it through
//! `tower::ServiceExt::oneshot` with the shared state attached.

use std::sync::{Arc, LazyLock};

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Path, Query, Request as AxumRequest, State};
use axum::response::{IntoResponse, Response as AxumResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use http::request::Parts;
use http::{HeaderValue, Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;
use tunnel_protocol::{
    ACCESS_TOKEN_PREFIX, ADMIN_TOKEN_PREFIX, CLIENT_TOKEN_PREFIX, CloseReason, ENROLL_CODE_PREFIX, IceServer,
    SERVICE_TOKEN_PREFIX, TUNNEL_TOKEN_PREFIX,
};
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

use crate::clients;
use crate::db::{
    Access, AccessMode, ClientRow, DeleteOutcome, HostHeaderMode, NewAccessLink, NewTunnel, PasswordRequired,
    PublicNotAllowed, ServiceRow, TtlTooLong, TunnelPatch, TunnelQuotaExceeded, TunnelRow,
};
use crate::ice;
use crate::password;
use crate::role::Role;
use crate::services;
use crate::state::AppState;
use crate::tokens::{self, now};
use crate::util::{Body, full, json_response};

mod client_routes;
pub mod device;
mod service_routes;
#[cfg(test)]
mod tests;

use client_routes::*;
use service_routes::*;

const MIN_LINK_TTL_S: u64 = 30;
const MIN_ICE_TTL_S: u64 = 60;
const MAX_LABEL_LEN: usize = 200;
const MAX_METADATA_BYTES: usize = 16 * 1024;
const ID_ATTEMPTS: usize = 16;
/// TURN username subject for credentials minted through the API.
const API_SUBJECT: &str = "api";

static ROUTER: LazyLock<Router<Arc<AppState>>> = LazyLock::new(build_router);

pub async fn handle<B>(state: Arc<AppState>, req: Request<B>) -> Response<Body>
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<crate::util::BoxError>,
{
    let router: Router = ROUTER.clone().with_state(state);
    let resp = match router.oneshot(req.map(axum::body::Body::new)).await {
        Ok(resp) => resp,
        Err(never) => match never {},
    };
    // axum's body is `!Sync` and `util::Body` requires `Sync`. API responses
    // are small JSON documents, so collecting them is cheaper than a wrapper.
    let (parts, body) = resp.into_parts();
    match body.collect().await {
        Ok(collected) => Response::from_parts(parts, full(collected.to_bytes())),
        Err(e) => {
            tracing::error!(error = %e, "collecting api response failed");
            let body =
                ErrorBody { error: ErrorDetail { code: "internal".into(), message: "internal server error".into() } };
            json_response(StatusCode::INTERNAL_SERVER_ERROR, &body)
        }
    }
}

fn build_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/openapi.json", get(openapi_json))
        .route("/v1/tunnels", post(create_tunnel).get(list_tunnels))
        .route("/v1/tunnels/{id}", get(get_tunnel).patch(patch_tunnel).delete(delete_tunnel))
        .route("/v1/tunnels/{id}/token", post(rotate_tunnel_token))
        .route("/v1/tunnels/{id}/access-links", post(create_access_link).get(list_access_links))
        .route("/v1/access-links/{id}", axum::routing::delete(delete_access_link))
        .route("/v1/tunnels/{id}/turn-credentials", post(turn_credentials))
        .route("/v1/clients", post(create_client).get(list_clients))
        .route("/v1/clients/enroll", post(enroll_client))
        .route("/v1/device/code", post(device::device_code))
        .route("/v1/device/token", post(device::device_token))
        .route("/v1/server", get(server_info))
        .route("/v1/clients/{name}", axum::routing::delete(delete_client).patch(rename_client))
        .route("/v1/services", post(create_service).get(list_services))
        .route("/v1/services/{name}", axum::routing::patch(patch_service).delete(delete_service))
        .route("/v1/services/{name}/token", post(rotate_service_token))
        .fallback(fallback)
}

// ------------------------------------------------------------------ errors

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorDetail {
    /// Machine-readable code, e.g. `not_found`, `tunnel_expired`, `validation`.
    pub code: String,
    pub message: String,
}

#[derive(Debug)]
pub struct ApiError {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into() }
    }

    pub(crate) fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "missing or invalid token")
    }

    pub(crate) fn not_found(what: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", format!("{what} not found"))
    }

    pub(crate) fn expired() -> Self {
        Self::new(StatusCode::CONFLICT, "tunnel_expired", "tunnel has expired or was deleted")
    }

    pub(crate) fn validation(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "validation", message)
    }

    pub(crate) fn internal(e: anyhow::Error) -> Self {
        tracing::error!(error = %format!("{e:#}"), "api request failed");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal server error")
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self::internal(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> AxumResponse {
        let body = ErrorBody { error: ErrorDetail { code: self.code.to_string(), message: self.message } };
        let mut resp = (self.status, Json(body)).into_response();
        resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if self.status == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        resp
    }
}

pub(crate) type ApiResult<T> = Result<T, ApiError>;

// -------------------------------------------------------------- extractors

/// Proof that the request carried the admin token.
pub struct Admin;

/// Who is calling a tunnel endpoint: the admin token (every tunnel), an
/// enrolled client's token or a service token (only tunnels that owner created).
#[derive(Debug, Clone)]
pub enum Caller {
    Admin,
    /// A machine, acting for the user who owns it.
    Client {
        id: String,
        name: String,
        user: ClientUser,
    },
    Service {
        id: String,
        name: String,
    },
}

/// The owner of a machine client, as far as tunnel rules need it.
#[derive(Debug, Clone)]
pub struct ClientUser {
    pub id: String,
    pub role: Role,
    pub can_public: bool,
    pub limits: crate::limits::Settings,
}

impl Caller {
    /// Owner id recorded on tunnels this caller creates; `None` for the admin.
    fn owner_id(&self) -> Option<&str> {
        match self {
            Self::Admin => None,
            Self::Client { id, .. } | Self::Service { id, .. } => Some(id),
        }
    }

    fn may_use(&self, row: &TunnelRow) -> bool {
        match self.owner_id() {
            None => true,
            Some(id) => row.client_id.as_deref() == Some(id),
        }
    }

    /// For logs: a client and a service may share a name.
    fn describe(&self) -> String {
        match self {
            Self::Admin => "admin".to_string(),
            Self::Client { name, user, .. } => format!("client:{name} (user {})", user.id),
            Self::Service { name, .. } => format!("service:{name}"),
        }
    }

    /// Public previews need the admin token, an admin's machine or a user
    /// allowed public previews, unless the server allows them for everyone.
    fn check_public(&self, mode: AccessMode, limits: &crate::config::Limits) -> ApiResult<()> {
        let allowed = match self {
            Self::Admin => true,
            Self::Client { user, .. } => user.role.is_admin() || user.can_public,
            Self::Service { .. } => false,
        };
        if mode == AccessMode::Public && !allowed && !limits.allow_public_for_clients {
            return Err(public_refused());
        }
        Ok(())
    }

    /// Longest tunnel lifetime this caller may set; `None`: unlimited (its
    /// tunnels may never expire). A machine follows its user's limit.
    fn tunnel_ttl_limit(&self, limits: &crate::config::Limits) -> Option<u64> {
        match self {
            Self::Client { user, .. } => crate::limits::Defaults::new(limits).resolve(
                crate::limits::Kind::TunnelTtl,
                user.role,
                user.limits.tunnel_ttl_s,
            ),
            _ => Some(limits.max_tunnel_ttl_s),
        }
    }

    /// The machine's user's role, for limit messages.
    fn account_role(&self) -> Option<Role> {
        match self {
            Self::Client { user, .. } => Some(user.role),
            _ => None,
        }
    }

    /// The expiry asked for with `ttl_s` (from now) or `never_expires`,
    /// checked against this caller's lifetime limit. `None`: neither given.
    fn requested_expiry(
        &self,
        ttl_s: Option<u64>,
        never_expires: bool,
        limits: &crate::config::Limits,
    ) -> ApiResult<Option<i64>> {
        let limit = self.tunnel_ttl_limit(limits);
        match (ttl_s, never_expires) {
            (Some(_), true) => Err(ApiError::validation("give ttl_s or never_expires, not both")),
            (None, false) => Ok(None),
            (None, true) => match limit {
                Some(limit) => Err(ttl_refused(limit, self.account_role(), true)),
                None => Ok(Some(crate::db::NEVER_EXPIRES)),
            },
            (Some(ttl), false) => {
                let max = limit.unwrap_or(crate::limits::MAX_TTL_S);
                if ttl < crate::limits::MIN_TUNNEL_TTL_S || (limit.is_none() && ttl > max) {
                    return Err(ApiError::validation(format!(
                        "ttl_s must be within {}..={max}",
                        crate::limits::MIN_TUNNEL_TTL_S
                    )));
                }
                if ttl > max {
                    return Err(ttl_refused(max, self.account_role(), false));
                }
                Ok(Some(now() + ttl as i64))
            }
        }
    }
}

/// A lifetime beyond the caller's limit (422 `tunnel_ttl_limit`).
fn ttl_refused(limit: u64, account: Option<Role>, never: bool) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "tunnel_ttl_limit",
        crate::limits::ttl_limit_message(limit, account, never),
    )
}

/// A refused new tunnel (429 `tunnel_quota`), naming the limit.
fn quota_refused(q: TunnelQuotaExceeded) -> ApiError {
    let message = match q {
        TunnelQuotaExceeded::Account { limit, role } => crate::limits::tunnel_limit_message(limit, role),
        TunnelQuotaExceeded::Machine { limit } => format!(
            "this machine's live-tunnel limit ({limit}, limits.max_tunnels_per_client) is reached; \
             delete a tunnel first (`tunnel unshare`, or the Tunnels page)"
        ),
        TunnelQuotaExceeded::Service { limit } => format!(
            "this service's live-tunnel quota ({limit}) is reached; delete a tunnel first, \
             or ask the server's operator to raise it (`tunnel-server service set`)"
        ),
    };
    ApiError::new(StatusCode::TOO_MANY_REQUESTS, "tunnel_quota", message)
}

fn public_refused() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "public_not_allowed",
        "public previews need an admin's permission on this server; use access links or password mode",
    )
}

/// The server's tunnel rules for the database to apply to an owner's
/// current permissions.
fn policy(limits: &crate::config::Limits) -> crate::db::Policy {
    crate::db::Policy {
        allow_all_public: limits.allow_public_for_clients,
        defaults: crate::limits::Defaults::new(limits),
    }
}

fn bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
}

impl FromRequestParts<Arc<AppState>> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or_else(ApiError::unauthorized)?;
        if token.starts_with(ADMIN_TOKEN_PREFIX) {
            return if tokens::hashes_equal(&tokens::hash_token(token), &state.config.admin_token_hash) {
                Ok(Self::Admin)
            } else {
                Err(ApiError::unauthorized())
            };
        }
        if token.starts_with(CLIENT_TOKEN_PREFIX)
            && token.len() <= 256
            && let Some(c) = state.db.client_by_token_hash(tokens::hash_token(token)).await?
        {
            return Ok(Self::Client {
                id: c.id,
                name: c.name,
                user: ClientUser { id: c.user_id, role: c.role, can_public: c.can_public, limits: c.limits },
            });
        }
        if token.starts_with(SERVICE_TOKEN_PREFIX)
            && token.len() <= 256
            && let Some((id, name)) = state.db.service_by_token_hash(tokens::hash_token(token)).await?
        {
            return Ok(Self::Service { id, name });
        }
        Err(ApiError::unauthorized())
    }
}

/// Peer address of the API request (set by the listener).
#[derive(Debug, Clone, Copy)]
pub struct PeerAddr(pub std::net::SocketAddr);

impl FromRequestParts<Arc<AppState>> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).filter(|t| t.starts_with(ADMIN_TOKEN_PREFIX)).ok_or_else(ApiError::unauthorized)?;
        if tokens::hashes_equal(&tokens::hash_token(token), &state.config.admin_token_hash) {
            Ok(Admin)
        } else {
            Err(ApiError::unauthorized())
        }
    }
}

/// `Json<T>` whose rejections use the API error shape (422).
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: AxumRequest, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(Self(v)),
            Err(rejection) => Err(json_rejection(rejection)),
        }
    }
}

fn json_rejection(rejection: JsonRejection) -> ApiError {
    ApiError::validation(rejection.body_text())
}

/// Parse an optional JSON body: empty means `T::default()`.
fn optional_json<T: DeserializeOwned + Default>(body: &Bytes) -> ApiResult<T> {
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(T::default());
    }
    serde_json::from_slice(body).map_err(|e| ApiError::validation(format!("invalid JSON body: {e}")))
}

// ----------------------------------------------------------------- schemas

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateTunnelRequest {
    /// A machine-readable tag (`tunnel share` sets `share-<host>`); matched
    /// exactly by `GET /v1/tunnels?label=`.
    #[serde(default)]
    pub label: Option<String>,
    /// Display name for people (dashboard, `tunnel status`): trimmed, at most
    /// 80 characters, no control characters. A label only: it never changes
    /// a URL and need not be unique. Empty means none.
    #[serde(default)]
    pub name: Option<String>,
    /// Lifetime in seconds (60 ..= the caller's limit, `GET /v1/server`
    /// `limits.max_tunnel_ttl_s`). Required unless `never_expires`.
    #[serde(default)]
    pub ttl_s: Option<u64>,
    /// A tunnel that never expires (until deleted), instead of `ttl_s`; only
    /// for machines whose account has an unlimited tunnel lifetime.
    #[serde(default)]
    pub never_expires: bool,
    /// Ports the sandbox may expose (default 8).
    #[serde(default)]
    pub max_ports: Option<u16>,
    #[serde(default)]
    pub host_header: Option<HostHeaderMode>,
    /// Inject TURN config into preview HTML (default true).
    #[serde(default)]
    pub inject_ice: Option<bool>,
    /// Opaque JSON stored with the tunnel.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub metadata: Option<serde_json::Value>,
    /// Who may open previews (default: access links only).
    #[serde(default)]
    pub access: Option<AccessRequest>,
}

/// Access setting. Access links work in every mode.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessRequest {
    /// `link`: access links only. `password`: links, or the username and
    /// password on the preview's login page. `public`: anyone with the URL.
    pub mode: AccessMode,
    /// Password mode only (1..=64 characters). On PATCH, omitted keeps the current one.
    #[serde(default)]
    pub username: Option<String>,
    /// Password mode only (8..=256 characters); never returned. On PATCH,
    /// omitted keeps the current one. A new password signs out everyone who
    /// logged in with the old one.
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AccessView {
    pub mode: AccessMode,
    /// Set in password mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateTunnelResponse {
    pub id: String,
    /// Returned once; only its hash is stored.
    pub tunnel_token: String,
    /// e.g. `{port}-ab12cd3efg.previews.example.com`
    pub host_template: String,
    /// Unix seconds; 253402300799 (9999-12-31) when `never_expires`.
    pub expires_at: i64,
    /// The tunnel never expires; it lives until deleted.
    #[serde(default)]
    pub never_expires: bool,
    /// The creating machine's account has reached its monthly traffic cap:
    /// visitors see "traffic limit reached" until it is raised or the month ends.
    #[serde(default)]
    pub traffic_limited: bool,
}

#[derive(Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchTunnelRequest {
    /// New lifetime from now, in seconds (a renewal, within the caller's
    /// current lifetime limit).
    #[serde(default)]
    pub ttl_s: Option<u64>,
    /// Make the tunnel never expire, instead of `ttl_s` (unlimited lifetime only).
    #[serde(default)]
    pub never_expires: bool,
    #[serde(default)]
    pub label: Option<String>,
    /// Rename (same rules as on create); `""` removes the name. Links keep working.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub host_header: Option<HostHeaderMode>,
    #[serde(default)]
    pub inject_ice: Option<bool>,
    /// Replace the access setting.
    #[serde(default)]
    pub access: Option<AccessRequest>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PortView {
    pub port: u16,
    pub host: String,
    pub connected: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TunnelView {
    pub id: String,
    pub label: Option<String>,
    /// Display name; absent when unnamed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    pub access: AccessView,
    #[schema(value_type = Option<Object>)]
    pub metadata: Option<serde_json::Value>,
    /// A control connection is live.
    pub connected: bool,
    /// Unix seconds when the live control connection was established.
    pub connected_since: Option<i64>,
    /// TTL elapsed; the purge job will tombstone it.
    pub expired: bool,
    /// Ports declared on the live connection (empty while disconnected).
    pub ports: Vec<PortView>,
    pub host_template: String,
    pub max_ports: u16,
    pub host_header: HostHeaderMode,
    pub inject_ice: bool,
    pub created_at: i64,
    /// Unix seconds; 253402300799 (9999-12-31) when `never_expires`.
    pub expires_at: i64,
    /// The tunnel never expires; it lives until deleted.
    pub never_expires: bool,
    pub last_seen_at: Option<i64>,
    /// Proxied bytes visitor → app (request bodies, WebSocket messages).
    pub bytes_in: u64,
    /// Proxied bytes app → visitor.
    pub bytes_out: u64,
    /// The owning machine's account has reached its monthly traffic cap.
    pub traffic_limited: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TunnelList {
    pub tunnels: Vec<TunnelView>,
    /// Pass as `cursor` to fetch the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateAccessLinkRequest {
    /// Link lifetime in seconds (30 ..= tunnel remaining lifetime).
    pub ttl_s: u64,
    /// Default true.
    #[serde(default)]
    pub single_use: Option<bool>,
    #[serde(default)]
    pub label: Option<String>,
    /// Gate session lifetime (default 12h), capped by the tunnel's expiry.
    #[serde(default)]
    pub session_ttl_s: Option<u64>,
    /// Port whose preview the link opens. Default: the lowest connected port
    /// at mint time, else the lowest connected port when the link is opened.
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AccessLinkResponse {
    pub id: String,
    /// The link to hand out: `https://<zone>/__access/{port}-{id}/tnacc_…`.
    /// It signs the visitor in on the zone host (which no preview controls)
    /// and redirects to the preview.
    pub url: String,
    pub expires_at: i64,
}

#[derive(Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnCredentialsRequest {
    /// Default: the browser TTL (1h); max: the sandbox TTL (24h).
    #[serde(default)]
    pub ttl_s: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TurnCredentialsResponse {
    #[serde(rename = "iceServers")]
    #[schema(value_type = Vec<Object>)]
    pub ice_servers: Vec<IceServer>,
    pub expires_at: u64,
    pub ttl_s: u64,
}

#[derive(OpenApi)]
#[openapi(
    info(title = "Tunnel management API"),
    paths(
        healthz,
        create_tunnel,
        list_tunnels,
        get_tunnel,
        patch_tunnel,
        delete_tunnel,
        rotate_tunnel_token,
        create_access_link,
        list_access_links,
        delete_access_link,
        turn_credentials,
        create_client,
        list_clients,
        delete_client,
        rename_client,
        enroll_client,
        create_service,
        list_services,
        patch_service,
        rotate_service_token,
        delete_service,
        server_info,
        device::device_code,
        device::device_token,
    ),
    components(schemas(
        Health,
        ErrorBody,
        ErrorDetail,
        CreateTunnelRequest,
        CreateTunnelResponse,
        AccessRequest,
        AccessView,
        AccessMode,
        CreateClientRequest,
        RenameClientRequest,
        CreateClientResponse,
        ClientView,
        ClientList,
        EnrollRequest,
        EnrollResponse,
        PatchTunnelRequest,
        PortView,
        TunnelView,
        TunnelList,
        CreateAccessLinkRequest,
        AccessLinkResponse,
        TurnCredentialsRequest,
        TurnCredentialsResponse,
        HostHeaderMode,
        TunnelTokenResponse,
        CreateServiceRequest,
        ServiceTokenResponse,
        ServiceView,
        ServiceList,
        PatchServiceRequest,
        AccessLinkView,
        AccessLinkList,
        ServerInfo,
        ServerLimits,
        AccountLimits,
        LimitUse,
        crate::traffic::TrafficView,
        device::DeviceCodeRequest,
        device::DeviceCodeResponse,
        device::DeviceTokenRequest,
    )),
    modifiers(&BearerAuth),
    security(("admin" = []))
)]
struct ApiDoc;

struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme("admin", SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)));
    }
}

// ---------------------------------------------------------------- handlers

/// Fail the health check when the certificate expires sooner than this
/// (renewal normally runs with a third of the lifetime left, ~30 days).
const HEALTH_MIN_CERT_DAYS: i64 = 7;
const HEALTH_DB_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Health {
    /// `ok` or `failing`.
    pub status: String,
    pub database: bool,
    /// Days until the served certificate expires (`None`: none loaded).
    pub certificate_days_left: Option<i64>,
    /// Server version, included only after authentication with the configured health token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[utoipa::path(
    get,
    path = "/healthz",
    params(("token" = Option<String>, Query, description = "Health token, for monitors that cannot send headers")),
    security(()),
    responses(
        (status = 200, body = Health, description = "Healthy; version is included only for a valid configured health token"),
        (status = 503, body = Health, description = "Database not answering, or certificate missing or expiring within 7 days"),
        (status = 404, description = "A health token is configured and none (or a wrong one) was presented; admin tokens are not accepted"),
    )
)]
async fn healthz(
    State(state): State<Arc<AppState>>,
    headers: http::HeaderMap,
    uri: http::Uri,
) -> Result<(StatusCode, Json<Health>), ApiError> {
    if let Some(expected) = &state.config.health_token_hash {
        let from_query = uri.query().and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes()).find(|(k, _)| k == "token").map(|(_, v)| v.into_owned())
        });
        let from_header = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|v| v.trim().to_string());
        let ok = [from_query, from_header].into_iter().flatten().any(|t| {
            let h = tokens::hash_token(&t);
            tokens::hashes_equal(&h, expected)
        });
        if !ok {
            // Indistinguishable from an unknown route.
            return Err(ApiError::not_found("route"));
        }
    }
    let database = tokio::time::timeout(
        HEALTH_DB_TIMEOUT,
        state.db.call(|c| Ok(c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?)),
    )
    .await
    .is_ok_and(|r| r.is_ok());
    let certificate_days_left = state.certs.not_after().map(|t| (t - now()).div_euclid(86_400));
    let healthy = database && certificate_days_left.is_some_and(|d| d >= HEALTH_MIN_CERT_DAYS);
    let status = if healthy { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    let body = Health {
        status: if healthy { "ok" } else { "failing" }.to_string(),
        database,
        certificate_days_left,
        version: state.config.health_token_hash.as_ref().map(|_| env!("CARGO_PKG_VERSION").to_string()),
    };
    Ok((status, Json(body)))
}

async fn openapi_json(_admin: Admin) -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServerInfo {
    pub version: String,
    /// `https://<api host>`: this API.
    pub api_origin: String,
    /// `wss://<tunnel host>`: where `tunnel` connects.
    pub control_origin: String,
    /// `https://<preview zone>`: access links and the sign-in page.
    pub gate_origin: String,
    /// `https://<ui host>`, when the web UI is enabled.
    pub ui_origin: Option<String>,
    /// `{port}-{id}.<zone>`; replace both placeholders.
    pub preview_host_template: String,
    /// The preview zone, the parent domain of every preview host.
    pub preview_zone: String,
    pub webrtc: bool,
    pub limits: ServerLimits,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServerLimits {
    /// Longest tunnel lifetime this caller may set; `null`: unlimited (it may
    /// create tunnels with `never_expires`).
    pub max_tunnel_ttl_s: Option<u64>,
    pub default_max_ports: u16,
    pub hard_max_ports: u16,
    pub default_session_ttl_s: u64,
    /// Whether this caller may create public previews.
    pub public_allowed: bool,
    /// This month's traffic of the caller's account (machine callers only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic: Option<crate::traffic::TrafficView>,
    /// The limits of the caller's account and its use (machine callers only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<AccountLimits>,
}

/// A machine's account: its limits (`null`: unlimited) and what it uses.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AccountLimits {
    pub role: String,
    /// Live tunnels across all the account's machines.
    pub tunnels: LimitUse,
    pub machines: LimitUse,
    /// Longest tunnel lifetime in seconds; `null`: tunnels may never expire.
    pub tunnel_ttl_s: Option<u64>,
    /// Monthly traffic in bytes (see `traffic` for this month's use).
    pub traffic_bytes: Option<u64>,
    /// Who can raise these: `an admin` or `the server's owner` (`null` for the owner).
    pub raised_by: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LimitUse {
    /// `null`: unlimited.
    pub limit: Option<u64>,
    pub used: u64,
}

/// Any bearer caller: where things live and what this caller may do.
#[utoipa::path(get, path = "/v1/server", responses((status = 200, body = ServerInfo), (status = 401, body = ErrorBody)))]
async fn server_info(State(state): State<Arc<AppState>>, caller: Caller) -> ApiResult<Json<ServerInfo>> {
    let cfg = &state.config;
    let limits = &cfg.limits;
    let (traffic, account) = match &caller {
        Caller::Client { user, .. } => {
            let effective = crate::limits::Defaults::new(limits).effective(user.role, &user.limits);
            let (machines, tunnels) = state.db.user_usage(user.id.clone()).await?;
            let account = AccountLimits {
                role: user.role.as_str().to_string(),
                tunnels: LimitUse { limit: effective.tunnels, used: tunnels },
                machines: LimitUse { limit: effective.machines, used: machines },
                tunnel_ttl_s: effective.tunnel_ttl_s,
                traffic_bytes: effective.traffic_bytes,
                raised_by: (user.role != Role::Owner).then(|| crate::limits::raiser(user.role).to_string()),
            };
            (Some(state.traffic.view(&state.db, &user.id).await?), Some(account))
        }
        _ => (None, None),
    };
    Ok(Json(ServerInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        api_origin: format!("https://{}", cfg.api_host),
        control_origin: format!("wss://{}", cfg.tunnel_host),
        gate_origin: format!("https://{}", cfg.preview_zone),
        ui_origin: cfg.ui_host.as_ref().map(|h| format!("https://{h}")),
        preview_host_template: format!("{{port}}-{{id}}.{}", cfg.preview_zone),
        preview_zone: cfg.preview_zone.clone(),
        webrtc: cfg.webrtc.enabled,
        limits: ServerLimits {
            max_tunnel_ttl_s: caller.tunnel_ttl_limit(limits),
            default_max_ports: limits.default_max_ports,
            hard_max_ports: limits.hard_max_ports,
            default_session_ttl_s: limits.default_session_ttl_s,
            public_allowed: caller.check_public(AccessMode::Public, limits).is_ok(),
            traffic,
            account,
        },
    }))
}

async fn fallback() -> ApiError {
    ApiError::not_found("route")
}

#[utoipa::path(
    post,
    path = "/v1/tunnels",
    request_body = CreateTunnelRequest,
    responses(
        (status = 201, description = "Tunnel created", body = CreateTunnelResponse),
        (status = 401, body = ErrorBody),
        (status = 403, description = "Public access requested by a client or service while `allow_public_for_clients` is off", body = ErrorBody),
        (status = 429, description = "Live-tunnel quota reached (`tunnel_quota`; clients: `max_tunnels_per_client` and their account's limit across its machines; services: their own `max_tunnels`); admin tokens are unlimited", body = ErrorBody),
        (status = 422, description = "Invalid request, or a lifetime beyond the caller's limit (`tunnel_ttl_limit`)", body = ErrorBody),
    )
)]
async fn create_tunnel(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    ApiJson(req): ApiJson<CreateTunnelRequest>,
) -> ApiResult<(StatusCode, Json<CreateTunnelResponse>)> {
    let limits = &state.config.limits;
    let never = req.never_expires;
    let expires_at = caller
        .requested_expiry(req.ttl_s, req.never_expires, limits)?
        .ok_or_else(|| ApiError::validation("ttl_s is required (or never_expires: true)"))?;
    let max_ports = req.max_ports.unwrap_or(limits.default_max_ports);
    if !(1..=limits.hard_max_ports).contains(&max_ports) {
        return Err(ApiError::validation(format!("max_ports must be within 1..={}", limits.hard_max_ports)));
    }
    validate_label(req.label.as_deref())?;
    let name = match req.name.as_deref() {
        Some(n) => tunnel_name(n)?,
        None => None,
    };
    if let Some(m) = &req.metadata
        && m.to_string().len() > MAX_METADATA_BYTES
    {
        return Err(ApiError::validation(format!("metadata must be at most {MAX_METADATA_BYTES} bytes")));
    }

    if let Some(a) = &req.access {
        caller.check_public(a.mode, limits)?;
    }
    let access = match req.access {
        Some(a) => build_access(a, None).await?,
        None => Access::default(),
    };
    let mode = access.mode;

    let id = fresh_tunnel_id(&state).await?;
    let token = tokens::random_token(TUNNEL_TOKEN_PREFIX);
    let row = state
        .db
        .create_tunnel_with(
            NewTunnel {
                id,
                token_hash: tokens::hash_token(&token),
                label: req.label,
                name,
                metadata: req.metadata,
                max_ports,
                host_header: req.host_header.unwrap_or(HostHeaderMode::Rewrite),
                inject_ice: req.inject_ice.unwrap_or(true),
                expires_at,
                access,
                client_id: caller.owner_id().map(str::to_string),
            },
            limits.max_tunnels_per_client,
            // Checked again in the INSERT transaction against the owner's
            // current role and permissions (the checks above may be stale).
            policy(limits),
        )
        .await
        .map_err(|e| {
            if e.is::<PublicNotAllowed>() {
                public_refused()
            } else if let Some(t) = e.downcast_ref::<TtlTooLong>() {
                ttl_refused(t.limit, t.account, never)
            } else if let Some(q) = e.downcast_ref::<TunnelQuotaExceeded>() {
                quota_refused(*q)
            } else {
                ApiError::internal(e)
            }
        })?
        // The client was deleted while this request was in flight.
        .ok_or_else(ApiError::unauthorized)?;
    // A cached negative lookup for this id (e.g. a probe) must not hide the new tunnel.
    state.invalidate_tunnel(&row.id);
    let by = caller.describe();
    tracing::info!(tunnel = %row.id, by, max_ports, access = mode.as_str(), expires_at = row.expires_at, "tunnel created");

    Ok((
        StatusCode::CREATED,
        Json(CreateTunnelResponse {
            host_template: state.config.host_template(&row.id),
            traffic_limited: row.user_id.as_deref().is_some_and(|u| state.traffic.user_blocked(u)),
            never_expires: row.expires_at == crate::db::NEVER_EXPIRES,
            id: row.id,
            tunnel_token: token,
            expires_at: row.expires_at,
        }),
    ))
}

/// Bounded keyset pagination. Cursors are the last tunnel id, or client or service name.
#[derive(Debug, Default, Deserialize)]
struct Pagination {
    limit: Option<u32>,
    cursor: Option<String>,
}

/// `GET /v1/tunnels` query: pagination plus an exact label filter.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TunnelQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    label: Option<String>,
}

fn pagination(query: Result<Query<Pagination>, QueryRejection>, clients: bool) -> ApiResult<(u32, Option<String>)> {
    let Query(query) = query.map_err(|e| ApiError::validation(e.body_text()))?;
    page_bounds(query, clients)
}

fn page_bounds(query: Pagination, clients: bool) -> ApiResult<(u32, Option<String>)> {
    let limit = query.limit.unwrap_or(100);
    if !(1..=500).contains(&limit) {
        return Err(ApiError::validation("limit must be within 1..=500"));
    }
    if let Some(cursor) = &query.cursor {
        let valid =
            if clients { crate::clients::validate_name(cursor).is_ok() } else { tokens::is_valid_tunnel_id(cursor) };
        if !valid {
            return Err(ApiError::validation("invalid cursor"));
        }
    }
    Ok((limit, query.cursor))
}

#[utoipa::path(
    get,
    path = "/v1/tunnels",
    params(
        ("limit" = Option<u32>, Query, description = "Page size (default 100)", minimum = 1, maximum = 500),
        ("cursor" = Option<String>, Query, description = "Opaque next_cursor returned by the previous page"),
        ("label" = Option<String>, Query, description = "Only tunnels whose label is exactly this value"),
    ),
    responses((status = 200, body = TunnelList), (status = 401, body = ErrorBody), (status = 422, body = ErrorBody))
)]
async fn list_tunnels(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    query: Result<Query<TunnelQuery>, QueryRejection>,
) -> ApiResult<Json<TunnelList>> {
    let Query(query) = query.map_err(|e| ApiError::validation(e.body_text()))?;
    validate_label(query.label.as_deref())?;
    let (limit, cursor) = page_bounds(Pagination { limit: query.limit, cursor: query.cursor }, false)?;
    // Stored bytes and unflushed ones from the same side of any flush.
    let _reading = state.traffic.reading().await;
    let mut rows =
        state.db.list_tunnels_page(caller.owner_id().map(str::to_string), query.label, cursor, limit).await?;
    let has_more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = if has_more { rows.last().map(|row| row.id.clone()) } else { None };
    let tunnels = rows.iter().map(|row| tunnel_view(&state, row)).collect();
    Ok(Json(TunnelList { tunnels, next_cursor }))
}

#[utoipa::path(
    get,
    path = "/v1/tunnels/{id}",
    params(("id" = String, Path, description = "Tunnel id")),
    responses((status = 200, body = TunnelView), (status = 401, body = ErrorBody), (status = 404, body = ErrorBody))
)]
async fn get_tunnel(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
) -> ApiResult<Json<TunnelView>> {
    let _reading = state.traffic.reading().await;
    let row = find_tunnel(&state, &caller, &id).await?;
    Ok(Json(tunnel_view(&state, &row)))
}

#[utoipa::path(
    patch,
    path = "/v1/tunnels/{id}",
    params(("id" = String, Path, description = "Tunnel id")),
    request_body = PatchTunnelRequest,
    responses(
        (status = 200, body = TunnelView),
        (status = 401, body = ErrorBody),
        (status = 403, description = "Switch to public access by a client or service while `allow_public_for_clients` is off", body = ErrorBody),
        (status = 404, body = ErrorBody),
        (status = 409, body = ErrorBody),
        (status = 422, body = ErrorBody),
    )
)]
async fn patch_tunnel(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<PatchTunnelRequest>,
) -> ApiResult<Json<TunnelView>> {
    let never = req.never_expires;
    let expires_at = caller.requested_expiry(req.ttl_s, req.never_expires, &state.config.limits)?;
    validate_label(req.label.as_deref())?;
    let name = req.name.as_deref().map(tunnel_name).transpose()?;
    // Expiry is revocation: an expired tunnel cannot be revived by extending it.
    let current = active_tunnel(&state, &caller, &id).await?;
    let keep_password_hash =
        req.access.as_ref().is_some_and(|a| a.mode == AccessMode::Password && a.password.is_none());
    let access = match req.access {
        Some(a) => Some(build_access(a, Some(&current.access)).await?),
        None => None,
    };

    let patch = TunnelPatch {
        expires_at,
        label: req.label,
        name,
        host_header: req.host_header,
        inject_ice: req.inject_ice,
        access,
        keep_password_hash,
        // The owner's current rules, applied in the update transaction: only a
        // switch into public is refused, so a public tunnel stays editable.
        owner_policy: caller.owner_id().map(|o| (o.to_string(), policy(&state.config.limits))),
    };
    let _reading = state.traffic.reading().await;
    let updated = state.db.update_tunnel(id.clone(), patch).await.map_err(|e| {
        if e.is::<PasswordRequired>() {
            ApiError::validation(e.to_string())
        } else if e.is::<PublicNotAllowed>() {
            public_refused()
        } else if let Some(t) = e.downcast_ref::<TtlTooLong>() {
            ttl_refused(t.limit, t.account, never)
        } else {
            ApiError::internal(e)
        }
    })?;
    let updated = updated.ok_or_else(|| ApiError::not_found("tunnel"))?;
    let row = updated.row;
    state.invalidate_tunnel(&id);
    if updated.grants_changed {
        // Recheck active upgrades only when their grants could have changed.
        state.invalidate_sessions();
        state.registry.rotate_gate_epoch(&id);
    }
    if updated.access_changed {
        tracing::info!(tunnel = %id, access = row.access.mode.as_str(), "tunnel access changed");
    }
    Ok(Json(tunnel_view(&state, &row)))
}

#[utoipa::path(
    delete,
    path = "/v1/tunnels/{id}",
    params(("id" = String, Path, description = "Tunnel id")),
    responses(
        (status = 204, description = "Deleted (or already deleted)"),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
async fn delete_tunnel(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !tokens::is_valid_tunnel_id(&id) {
        return Err(ApiError::not_found("tunnel"));
    }
    if caller.owner_id().is_some() {
        // Clients and services may delete only their own live rows (tombstones have no owner).
        find_tunnel(&state, &caller, &id).await?;
    }
    match state.delete_tunnel(&id, CloseReason::Deleted).await? {
        DeleteOutcome::Deleted => {
            tracing::info!(tunnel = %id, "tunnel deleted");
            Ok(StatusCode::NO_CONTENT)
        }
        DeleteOutcome::AlreadyTombstoned => Ok(StatusCode::NO_CONTENT),
        DeleteOutcome::NotFound => Err(ApiError::not_found("tunnel")),
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TunnelTokenResponse {
    pub id: String,
    /// The new tunnel token, returned once. The previous token no longer
    /// connects, and a live connection made with it is closed (`replaced`).
    pub tunnel_token: String,
}

#[utoipa::path(
    post,
    path = "/v1/tunnels/{id}/token",
    params(("id" = String, Path, description = "Tunnel id")),
    responses(
        (status = 200, body = TunnelTokenResponse),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
        (status = 409, body = ErrorBody),
    )
)]
async fn rotate_tunnel_token(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
) -> ApiResult<Json<TunnelTokenResponse>> {
    let tunnel = active_tunnel(&state, &caller, &id).await?;
    let token = tokens::random_token(TUNNEL_TOKEN_PREFIX);
    let hash = tokens::hash_token(&token);
    // Registration takes the same lock and checks the current token, so under
    // it `hash` is the newest token: only older holders are closed, and no
    // handshake that started with an older token can register later. A
    // detached task keeps the update and the close under the lock even if the
    // request is dropped mid-way.
    let rotated = tokio::spawn({
        let state = state.clone();
        let id = tunnel.id.clone();
        async move {
            let _guard = state.token_lock(&id).lock().await;
            if !state.db.rotate_tunnel_token(id.clone(), hash.clone()).await? {
                return Ok::<_, anyhow::Error>(false);
            }
            if let Some(live) = state.registry.get(&id)
                && !tokens::hashes_equal(&live.token_hash, &hash)
            {
                live.close(CloseReason::Replaced);
            }
            state.invalidate_tunnel(&id);
            Ok(true)
        }
    })
    .await
    .map_err(|e| ApiError::internal(e.into()))??;
    if !rotated {
        // Expired or deleted since the check above.
        return Err(ApiError::expired());
    }
    tracing::info!(tunnel = %tunnel.id, by = caller.describe(), "tunnel token rotated");
    Ok(Json(TunnelTokenResponse { id: tunnel.id, tunnel_token: token }))
}

#[utoipa::path(
    post,
    path = "/v1/tunnels/{id}/access-links",
    params(("id" = String, Path, description = "Tunnel id")),
    request_body = CreateAccessLinkRequest,
    responses(
        (status = 201, body = AccessLinkResponse),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
        (status = 409, body = ErrorBody),
        (status = 422, body = ErrorBody),
    )
)]
async fn create_access_link(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<CreateAccessLinkRequest>,
) -> ApiResult<(StatusCode, Json<AccessLinkResponse>)> {
    let tunnel = active_tunnel(&state, &caller, &id).await?;
    Ok((StatusCode::CREATED, Json(mint_access_link(&state, &tunnel, req, None).await?)))
}

/// Mint an access link for `tunnel` (already authorized and unexpired).
/// From the web UI, `ui` is `(user id, session id hash)`: the session and the
/// user's right to the tunnel are checked again when the link is stored.
pub(crate) async fn mint_access_link(
    state: &AppState,
    tunnel: &TunnelRow,
    req: CreateAccessLinkRequest,
    ui: Option<(String, String)>,
) -> ApiResult<AccessLinkResponse> {
    mint_link(state, tunnel, req, ui, None).await
}

/// An owner link for the web UI's Open button: single use, bound to `port`,
/// for `user`'s own tunnel only (checked again when it is stored).
pub(crate) async fn mint_owner_link(
    state: &AppState,
    tunnel: &TunnelRow,
    port: u16,
    ttl_s: u64,
    label: &str,
    ui: (String, String),
) -> ApiResult<AccessLinkResponse> {
    let req = CreateAccessLinkRequest {
        ttl_s,
        single_use: Some(true),
        label: Some(label.to_string()),
        session_ttl_s: None,
        port: Some(port),
    };
    mint_link(state, tunnel, req, Some(ui), Some(port)).await
}

async fn mint_link(
    state: &AppState,
    tunnel: &TunnelRow,
    req: CreateAccessLinkRequest,
    ui: Option<(String, String)>,
    owner_port: Option<u16>,
) -> ApiResult<AccessLinkResponse> {
    let t = now();
    let remaining = (tunnel.expires_at - t).max(0) as u64;
    if req.ttl_s < MIN_LINK_TTL_S || req.ttl_s > remaining {
        return Err(ApiError::validation(format!(
            "ttl_s must be within {MIN_LINK_TTL_S}..={remaining} (the tunnel's remaining lifetime)"
        )));
    }
    let session_ttl_s = match req.session_ttl_s {
        Some(0) => return Err(ApiError::validation("session_ttl_s must be positive")),
        Some(s) => s,
        None => state.config.limits.default_session_ttl_s,
    }
    .min(remaining);
    validate_label(req.label.as_deref())?;
    if req.port == Some(0) {
        return Err(ApiError::validation("port must be 1..=65535"));
    }
    let port = req.port.or_else(|| state.registry.get(&tunnel.id).and_then(|l| l.ports().first().copied()));

    let link_id = tokens::random_link_id();
    let token = tokens::random_token(ACCESS_TOKEN_PREFIX);
    let expires_at = t + req.ttl_s as i64;
    let single_use = req.single_use.unwrap_or(true);
    let link = NewAccessLink {
        id: link_id.clone(),
        tunnel_id: tunnel.id.clone(),
        token_hash: tokens::hash_token(&token),
        single_use,
        label: req.label,
        session_ttl_s: session_ttl_s as i64,
        expires_at,
        owner_port,
    };
    match ui {
        Some((user, session)) => {
            if !state.db.create_access_link_for(link, user, session).await? {
                return Err(ApiError::not_found("tunnel"));
            }
        }
        None => state.db.create_access_link(link).await?,
    }
    let kind = if owner_port.is_some() { "owner" } else { "visitor" };
    tracing::info!(tunnel = %tunnel.id, link = %link_id, kind, single_use, expires_at, "access link created");
    Ok(AccessLinkResponse {
        id: link_id,
        url: crate::gatehost::access_url(&state.config.preview_zone, &tunnel.id, port, &token),
        expires_at,
    })
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AccessLinkView {
    pub id: String,
    pub label: Option<String>,
    pub single_use: bool,
    /// When a single-use link was redeemed.
    pub used_at: Option<i64>,
    pub session_ttl_s: i64,
    pub created_at: i64,
    pub expires_at: i64,
    /// `visitor`, or `owner`: made by the web UI's Open button for the
    /// tunnel's own user, bound to one port.
    #[serde(default = "visitor_kind")]
    pub kind: String,
}

fn visitor_kind() -> String {
    "visitor".into()
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AccessLinkList {
    /// Newest first. The link URLs are not stored and cannot be listed.
    pub links: Vec<AccessLinkView>,
}

#[utoipa::path(
    get,
    path = "/v1/tunnels/{id}/access-links",
    params(("id" = String, Path, description = "Tunnel id")),
    responses((status = 200, body = AccessLinkList), (status = 401, body = ErrorBody), (status = 404, body = ErrorBody))
)]
async fn list_access_links(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
) -> ApiResult<Json<AccessLinkList>> {
    let tunnel = find_tunnel(&state, &caller, &id).await?;
    Ok(Json(access_link_list(&state, &tunnel.id).await?))
}

pub(crate) async fn access_link_list(state: &AppState, tunnel_id: &str) -> ApiResult<AccessLinkList> {
    let links = state
        .db
        .list_access_links(tunnel_id.to_string())
        .await?
        .into_iter()
        .map(|l| AccessLinkView {
            id: l.id,
            label: l.label,
            single_use: l.single_use,
            used_at: l.used_at,
            session_ttl_s: l.session_ttl_s,
            created_at: l.created_at,
            expires_at: l.expires_at,
            kind: l.kind,
        })
        .collect();
    Ok(AccessLinkList { links })
}

/// Revoke link `id` of `tunnel_id` and everything it granted.
pub(crate) async fn revoke_access_link(state: &AppState, id: &str, tunnel_id: &str) -> ApiResult<()> {
    if !state.db.delete_access_link(id.to_string()).await? {
        return Err(ApiError::not_found("access link"));
    }
    state.invalidate_sessions();
    state.registry.rotate_gate_epoch(tunnel_id);
    tracing::info!(link = %id, "access link revoked");
    Ok(())
}

#[utoipa::path(
    delete,
    path = "/v1/access-links/{id}",
    params(("id" = String, Path, description = "Access link id")),
    responses(
        (status = 204, description = "Revoked, along with the gate sessions it created"),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
async fn delete_access_link(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let tunnel = state.db.access_link_tunnel(id.clone()).await?.ok_or_else(|| ApiError::not_found("access link"))?;
    if caller.owner_id().is_some() && find_tunnel(&state, &caller, &tunnel).await.is_err() {
        return Err(ApiError::not_found("access link"));
    }
    revoke_access_link(&state, &id, &tunnel).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/v1/tunnels/{id}/turn-credentials",
    params(("id" = String, Path, description = "Tunnel id")),
    request_body(content = TurnCredentialsRequest, description = "Optional; empty body uses the defaults"),
    responses(
        (status = 200, body = TurnCredentialsResponse),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
        (status = 409, body = ErrorBody, description = "Tunnel expired, or WebRTC disabled"),
        (status = 422, body = ErrorBody),
    )
)]
async fn turn_credentials(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<Json<TurnCredentialsResponse>> {
    let req: TurnCredentialsRequest = optional_json(&body)?;
    let webrtc = &state.config.webrtc;
    if !webrtc.enabled {
        return Err(ApiError::new(StatusCode::CONFLICT, "webrtc_disabled", "WebRTC is not enabled on this server"));
    }
    let ttl_s = req.ttl_s.unwrap_or(webrtc.browser_ttl_s);
    if !(MIN_ICE_TTL_S..=webrtc.sandbox_ttl_s).contains(&ttl_s) {
        return Err(ApiError::validation(format!("ttl_s must be within {MIN_ICE_TTL_S}..={}", webrtc.sandbox_ttl_s)));
    }
    let tunnel = active_tunnel(&state, &caller, &id).await?;
    let ice = ice::mint(&state.config, &tunnel.id, API_SUBJECT, ttl_s);
    Ok(Json(TurnCredentialsResponse { ice_servers: ice.ice_servers, expires_at: ice.expires_at, ttl_s: ice.ttl_s }))
}

// ----------------------------------------------------------------- helpers

/// Longest tunnel display name, in characters.
pub const MAX_NAME_CHARS: usize = 80;

/// Characters a display name may not contain besides control characters:
/// every Unicode format character (zero-width, bidi, tags, …), line and
/// paragraph separators and the invisible Hangul fillers, which could blank
/// out or disguise a name or reorder the text around it in a terminal or a page.
fn hidden_char(c: char) -> bool {
    matches!(c, '\u{00AD}' | '\u{034F}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}'
            | '\u{0890}'..='\u{0891}' | '\u{08E2}' | '\u{115F}'..='\u{1160}' | '\u{17B4}'..='\u{17B5}' | '\u{180E}'
            | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{3164}' | '\u{FEFF}'
            | '\u{FFA0}' | '\u{FFF9}'..='\u{FFFB}' | '\u{110BD}' | '\u{110CD}' | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}' | '\u{E0001}' | '\u{E0020}'..='\u{E007F}')
}

/// A tunnel display name as stored: trimmed; empty is no name (`None`).
pub fn tunnel_name(raw: &str) -> ApiResult<Option<String>> {
    let name = raw.trim();
    if name.is_empty() {
        return Ok(None);
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(ApiError::validation(format!("name must be at most {MAX_NAME_CHARS} characters")));
    }
    if name.chars().any(|c| c.is_control() || hidden_char(c)) {
        return Err(ApiError::validation("name must not contain control, zero-width or bidi characters"));
    }
    Ok(Some(name.to_string()))
}

fn validate_label(label: Option<&str>) -> ApiResult<()> {
    match label {
        Some(l) if l.chars().count() > MAX_LABEL_LEN => {
            Err(ApiError::validation(format!("label must be at most {MAX_LABEL_LEN} characters")))
        }
        _ => Ok(()),
    }
}

/// Validate an access request; hashes a new password. `current` is the stored
/// setting on PATCH, which supplies an omitted username and permits keeping
/// the password in the update transaction.
async fn build_access(req: AccessRequest, current: Option<&Access>) -> ApiResult<Access> {
    if req.mode != AccessMode::Password {
        if req.username.is_some() || req.password.is_some() {
            return Err(ApiError::validation("username and password apply only to access mode \"password\""));
        }
        return Ok(Access { mode: req.mode, password_user: None, password_hash: None });
    }
    let current = current.filter(|c| c.mode == AccessMode::Password);
    let username = match req.username.or_else(|| current.and_then(|c| c.password_user.clone())) {
        Some(u) => u,
        None => return Err(ApiError::validation("access.username is required for password mode")),
    };
    let len = username.chars().count();
    if !(1..=password::MAX_USERNAME_LEN).contains(&len) || username.chars().any(char::is_control) {
        return Err(ApiError::validation(format!(
            "access.username must be 1..={} characters without control characters",
            password::MAX_USERNAME_LEN
        )));
    }
    let password_hash = match req.password {
        Some(p) => {
            let len = p.chars().count();
            if !(password::MIN_PASSWORD_LEN..=password::MAX_PASSWORD_LEN).contains(&len) {
                return Err(ApiError::validation(format!(
                    "access.password must be {}..={} characters",
                    password::MIN_PASSWORD_LEN,
                    password::MAX_PASSWORD_LEN
                )));
            }
            Some(password::hash(p).await?)
        }
        // PATCH carries preservation to the transaction; never copy a hash
        // from this earlier read over a concurrent password rotation.
        None if current.is_some_and(|c| c.password_hash.is_some()) => None,
        None => return Err(ApiError::validation("access.password is required for password mode")),
    };
    Ok(Access { mode: AccessMode::Password, password_user: Some(username), password_hash })
}

/// Ids are never reused: retry while the id belongs to a tunnel or a tombstone.
async fn fresh_tunnel_id(state: &AppState) -> ApiResult<String> {
    for _ in 0..ID_ATTEMPTS {
        let id = tokens::random_tunnel_id();
        if !state.db.id_taken(id.clone()).await? {
            return Ok(id);
        }
    }
    Err(ApiError::internal(anyhow::anyhow!("could not allocate an unused tunnel id")))
}

/// Tunnel row (expired or not) straight from the database; 404 if unknown or tombstoned.
/// A tunnel the caller may use; another client's tunnel is "not found".
async fn find_tunnel(state: &AppState, caller: &Caller, id: &str) -> ApiResult<TunnelRow> {
    if !tokens::is_valid_tunnel_id(id) {
        return Err(ApiError::not_found("tunnel"));
    }
    match state.db.get_tunnel(id.to_string()).await? {
        Some(row) if caller.may_use(&row) => Ok(row),
        _ => Err(ApiError::not_found("tunnel")),
    }
}

/// Unexpired tunnel; 409 if expired or tombstoned, 404 if never existed.
async fn active_tunnel(state: &AppState, caller: &Caller, id: &str) -> ApiResult<TunnelRow> {
    match find_tunnel(state, caller, id).await {
        Ok(row) if row.is_expired() => Err(ApiError::expired()),
        Ok(row) => Ok(row),
        // Tombstones carry no owner, so only the admin learns that an id ended.
        Err(e)
            if e.status == StatusCode::NOT_FOUND
                && tokens::is_valid_tunnel_id(id)
                && matches!(caller, Caller::Admin) =>
        {
            if state.db.is_tombstoned(id.to_string()).await? {
                Err(ApiError::expired())
            } else {
                Err(e)
            }
        }
        Err(e) => Err(e),
    }
}

pub(crate) fn tunnel_view(state: &AppState, row: &TunnelRow) -> TunnelView {
    let live = state.registry.get(&row.id);
    let unflushed = state.traffic.unflushed(&row.id);
    let ports = live
        .as_ref()
        .map(|l| {
            l.ports()
                .into_iter()
                .map(|port| PortView { port, host: state.preview_host(port, &row.id), connected: true })
                .collect()
        })
        .unwrap_or_default();
    TunnelView {
        id: row.id.clone(),
        label: row.label.clone(),
        name: row.name.clone(),
        access: AccessView { mode: row.access.mode, username: row.access.password_user.clone() },
        metadata: row.metadata.clone(),
        connected: live.is_some(),
        connected_since: live.as_ref().map(|l| l.connected_at),
        expired: row.is_expired(),
        ports,
        host_template: state.config.host_template(&row.id),
        max_ports: row.max_ports,
        host_header: row.host_header,
        inject_ice: row.inject_ice,
        created_at: row.created_at,
        expires_at: row.expires_at,
        never_expires: row.expires_at == crate::db::NEVER_EXPIRES,
        last_seen_at: row.last_seen_at,
        bytes_in: row.bytes_in.max(0) as u64 + unflushed.0,
        bytes_out: row.bytes_out.max(0) as u64 + unflushed.1,
        traffic_limited: row.user_id.as_deref().is_some_and(|u| state.traffic.user_blocked(u)),
    }
}
