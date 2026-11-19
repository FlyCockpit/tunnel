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
use crate::services;
use crate::state::AppState;
use crate::tokens::{self, now};
use crate::ui::store::Role;
use crate::util::{Body, full, json_response};

const MIN_TUNNEL_TTL_S: u64 = 60;
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
        .route("/v1/device/code", post(crate::device::device_code))
        .route("/v1/device/token", post(crate::device::device_token))
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

    /// Longest tunnel lifetime this caller may set: members are capped lower.
    fn max_tunnel_ttl_s(&self, limits: &crate::config::Limits) -> u64 {
        match self {
            Self::Client { user, .. } if user.role == Role::Member => {
                limits.max_tunnel_ttl_s.min(limits.member_max_tunnel_ttl_s)
            }
            _ => limits.max_tunnel_ttl_s,
        }
    }
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
        member_max_ttl_s: i64::try_from(limits.max_tunnel_ttl_s.min(limits.member_max_tunnel_ttl_s))
            .unwrap_or(i64::MAX),
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
                user: ClientUser { id: c.user_id, role: c.role, can_public: c.can_public },
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
    #[serde(default)]
    pub label: Option<String>,
    /// Lifetime in seconds (60 ..= server max).
    pub ttl_s: u64,
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
    /// Unix seconds.
    pub expires_at: i64,
    /// The creating machine's account has reached its monthly traffic cap:
    /// visitors see "traffic limit reached" until it is raised or the month ends.
    #[serde(default)]
    pub traffic_limited: bool,
}

#[derive(Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchTunnelRequest {
    /// New lifetime from now, in seconds.
    #[serde(default)]
    pub ttl_s: Option<u64>,
    #[serde(default)]
    pub label: Option<String>,
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
    pub expires_at: i64,
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
        crate::device::device_code,
        crate::device::device_token,
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
        crate::traffic::TrafficView,
        crate::device::DeviceCodeRequest,
        crate::device::DeviceCodeResponse,
        crate::device::DeviceTokenRequest,
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
    pub max_tunnel_ttl_s: u64,
    pub default_max_ports: u16,
    pub hard_max_ports: u16,
    pub default_session_ttl_s: u64,
    /// Whether this caller may create public previews.
    pub public_allowed: bool,
    /// This month's traffic of the caller's account (machine callers only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic: Option<crate::traffic::TrafficView>,
}

/// Any bearer caller: where things live and what this caller may do.
#[utoipa::path(get, path = "/v1/server", responses((status = 200, body = ServerInfo), (status = 401, body = ErrorBody)))]
async fn server_info(State(state): State<Arc<AppState>>, caller: Caller) -> ApiResult<Json<ServerInfo>> {
    let cfg = &state.config;
    let limits = &cfg.limits;
    let traffic = match &caller {
        Caller::Client { user, .. } => Some(crate::traffic::view(&state, &user.id).await?),
        _ => None,
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
            max_tunnel_ttl_s: caller.max_tunnel_ttl_s(limits),
            default_max_ports: limits.default_max_ports,
            hard_max_ports: limits.hard_max_ports,
            default_session_ttl_s: limits.default_session_ttl_s,
            public_allowed: caller.check_public(AccessMode::Public, limits).is_ok(),
            traffic,
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
        (status = 429, description = "Live-tunnel quota reached (clients: `max_tunnels_per_client`; services: their own `max_tunnels`); admin tokens are unlimited", body = ErrorBody),
        (status = 422, body = ErrorBody),
    )
)]
async fn create_tunnel(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    ApiJson(req): ApiJson<CreateTunnelRequest>,
) -> ApiResult<(StatusCode, Json<CreateTunnelResponse>)> {
    let limits = &state.config.limits;
    validate_tunnel_ttl(req.ttl_s, caller.max_tunnel_ttl_s(limits))?;
    let max_ports = req.max_ports.unwrap_or(limits.default_max_ports);
    if !(1..=limits.hard_max_ports).contains(&max_ports) {
        return Err(ApiError::validation(format!("max_ports must be within 1..={}", limits.hard_max_ports)));
    }
    validate_label(req.label.as_deref())?;
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
                metadata: req.metadata,
                max_ports,
                host_header: req.host_header.unwrap_or(HostHeaderMode::Rewrite),
                inject_ice: req.inject_ice.unwrap_or(true),
                expires_at: now() + req.ttl_s as i64,
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
            } else if e.is::<TtlTooLong>() {
                ApiError::validation("ttl_s is longer than this account may set")
            } else if e.is::<TunnelQuotaExceeded>() {
                ApiError::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "tunnel_quota",
                    "live-tunnel quota reached; delete a tunnel or ask an admin for a higher limit",
                )
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
    if let Some(ttl) = req.ttl_s {
        validate_tunnel_ttl(ttl, caller.max_tunnel_ttl_s(&state.config.limits))?;
    }
    validate_label(req.label.as_deref())?;
    // Expiry is revocation: an expired tunnel cannot be revived by extending it.
    let current = active_tunnel(&state, &caller, &id).await?;
    let keep_password_hash =
        req.access.as_ref().is_some_and(|a| a.mode == AccessMode::Password && a.password.is_none());
    let access = match req.access {
        Some(a) => Some(build_access(a, Some(&current.access)).await?),
        None => None,
    };

    let patch = TunnelPatch {
        expires_at: req.ttl_s.map(|ttl| now() + ttl as i64),
        label: req.label,
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
        } else if e.is::<TtlTooLong>() {
            ApiError::validation("ttl_s is longer than this account may set")
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
    };
    match ui {
        Some((user, session)) => {
            if !state.db.create_access_link_for(link, user, session).await? {
                return Err(ApiError::not_found("tunnel"));
            }
        }
        None => state.db.create_access_link(link).await?,
    }
    tracing::info!(tunnel = %tunnel.id, link = %link_id, single_use, expires_at, "access link created");
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

fn validate_tunnel_ttl(ttl_s: u64, max: u64) -> ApiResult<()> {
    if (MIN_TUNNEL_TTL_S..=max).contains(&ttl_s) {
        Ok(())
    } else {
        Err(ApiError::validation(format!("ttl_s must be within {MIN_TUNNEL_TTL_S}..={max}")))
    }
}

fn validate_label(label: Option<&str>) -> ApiResult<()> {
    match label {
        Some(l) if l.chars().count() > MAX_LABEL_LEN => {
            Err(ApiError::validation(format!("label must be at most {MAX_LABEL_LEN} characters")))
        }
        _ => Ok(()),
    }
}

// ----------------------------------------------------------------- clients

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateClientRequest {
    /// 1..=64 characters: letters, digits, `.`, `_`, `-`.
    pub name: String,
    /// The user who owns the machine (default: the owner).
    #[serde(default)]
    pub user: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateClientResponse {
    pub name: String,
    /// `<code>@<host>`: paste at the `tunnel login` prompt on the
    /// client machine. Works once, until `expires_at`.
    pub login_code: String,
    /// The same as a single command (puts the code in process listings and history).
    pub login_command: String,
    /// Unix seconds.
    pub expires_at: i64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ClientView {
    pub name: String,
    /// The user who owns this machine.
    pub user: String,
    /// The login code has been used.
    pub enrolled: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// Unexpired tunnels this client created.
    pub tunnels: i64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ClientList {
    pub clients: Vec<ClientView>,
    /// Pass as `cursor` to fetch the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    /// `tnenr_…` code from `client add`.
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct EnrollResponse {
    pub name: String,
    /// Long-lived client token (`tncli_…`), shown once.
    pub token: String,
    /// `https://<api host>`
    pub api: String,
    /// `wss://<tunnel host>`
    pub server: String,
}

impl From<ClientRow> for ClientView {
    fn from(c: ClientRow) -> Self {
        Self {
            name: c.name,
            user: c.user,
            enrolled: c.enrolled,
            created_at: c.created_at,
            last_used_at: c.last_used_at,
            tunnels: c.tunnels,
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/clients",
    request_body = CreateClientRequest,
    responses((status = 201, body = CreateClientResponse), (status = 401, body = ErrorBody), (status = 409, body = ErrorBody), (status = 422, body = ErrorBody))
)]
async fn create_client(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    ApiJson(req): ApiJson<CreateClientRequest>,
) -> ApiResult<(StatusCode, Json<CreateClientResponse>)> {
    let user_id = match &req.user {
        Some(name) => state.db.user_by_name(name.clone()).await?.map(|u| u.id),
        // Created without a password on a server used without the web UI.
        None => Some(state.db.ensure_owner().await?.id),
    }
    .ok_or_else(|| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "no_user", "no such user"))?;
    match clients::add(&state.db, &state.config, &req.name, &user_id, None).await {
        Ok(e) => Ok((
            StatusCode::CREATED,
            Json(CreateClientResponse {
                name: e.name,
                login_code: e.login_code,
                login_command: e.login_command,
                expires_at: e.expires_at,
            }),
        )),
        Err(clients::AddError::Invalid(m)) => Err(ApiError::validation(m)),
        Err(clients::AddError::Taken) => {
            Err(ApiError::new(StatusCode::CONFLICT, "client_exists", "a client with this name exists; delete it first"))
        }
        Err(clients::AddError::Quota) => Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "client_quota",
            "this user has as many machines as allowed",
        )),
        Err(clients::AddError::NoUser) => {
            Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "no_user", "the user is unknown or disabled"))
        }
        Err(clients::AddError::Other(e)) => Err(e.into()),
    }
}

#[utoipa::path(
    get, path = "/v1/clients",
    params(
        ("limit" = Option<u32>, Query, description = "Page size (default 100)", minimum = 1, maximum = 500),
        ("cursor" = Option<String>, Query, description = "Opaque next_cursor returned by the previous page"),
    ),
    responses((status = 200, body = ClientList), (status = 401, body = ErrorBody), (status = 422, body = ErrorBody))
)]
async fn list_clients(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    query: Result<Query<Pagination>, QueryRejection>,
) -> ApiResult<Json<ClientList>> {
    let (limit, cursor) = pagination(query, true)?;
    let mut rows = state.db.list_clients_page(cursor, limit).await?;
    let has_more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = if has_more { rows.last().map(|row| row.name.clone()) } else { None };
    let clients = rows.into_iter().map(ClientView::from).collect();
    Ok(Json(ClientList { clients, next_cursor }))
}

#[utoipa::path(
    delete,
    path = "/v1/clients/{name}",
    params(("name" = String, Path, description = "Client name")),
    responses((status = 204, description = "Deleted; its token stops working and its tunnels close"), (status = 401, body = ErrorBody), (status = 404, body = ErrorBody))
)]
async fn delete_client(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    let tunnels = state.db.delete_client(name.clone()).await?.ok_or_else(|| ApiError::not_found("client"))?;
    for id in &tunnels {
        state.delete_tunnel(id, CloseReason::Deleted).await?;
    }
    tracing::info!(client = %name, tunnels = tunnels.len(), "client deleted");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RenameClientRequest {
    /// The new name: 1..=64 characters: letters, digits, `.`, `_`, `-`.
    pub name: String,
}

#[utoipa::path(
    patch,
    path = "/v1/clients/{name}",
    params(("name" = String, Path, description = "Client name")),
    request_body = RenameClientRequest,
    responses(
        (status = 200, body = RenameClientRequest, description = "Renamed; its token and tunnels are unchanged"),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
        (status = 409, body = ErrorBody),
        (status = 422, body = ErrorBody),
    )
)]
async fn rename_client(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path(name): Path<String>,
    ApiJson(req): ApiJson<RenameClientRequest>,
) -> ApiResult<Json<RenameClientRequest>> {
    clients::validate_new_name(&req.name).map_err(ApiError::validation)?;
    match state.db.rename_client(name.clone(), req.name.clone(), None).await? {
        Ok(()) => {}
        Err(crate::ui::store::RenameError::Taken) => {
            return Err(ApiError::new(StatusCode::CONFLICT, "client_exists", "a client with this name exists"));
        }
        Err(_) => return Err(ApiError::not_found("client")),
    }
    if name != req.name {
        let _ =
            state.db.audit(None, "machine_renamed", Some(format!("{name} -> {} (admin token)", req.name)), None).await;
    }
    tracing::info!(client = %name, new = %req.name, "client renamed");
    Ok(Json(req))
}

/// Unauthenticated: the one-time code is the credential. Shares the
/// access-link rate limit per IP.
#[utoipa::path(
    post,
    path = "/v1/clients/enroll",
    security(()),
    request_body = EnrollRequest,
    responses((status = 200, body = EnrollResponse), (status = 401, body = ErrorBody), (status = 429, body = ErrorBody))
)]
async fn enroll_client(
    State(state): State<Arc<AppState>>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiJson(req): ApiJson<EnrollRequest>,
) -> ApiResult<Json<EnrollResponse>> {
    if let Some(axum::Extension(PeerAddr(addr))) = peer
        && !state.access_limiter.check(addr.ip())
    {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many attempts; wait a minute"));
    }
    let code = req.code.trim();
    if !code.starts_with(ENROLL_CODE_PREFIX) || code.len() > 256 {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid_code", "invalid, used, or expired login code"));
    }
    let token = tokens::random_token(CLIENT_TOKEN_PREFIX);
    match state.db.enroll_client(tokens::hash_token(code), tokens::hash_token(&token)).await? {
        Some(name) => {
            tracing::info!(client = %name, "client enrolled");
            Ok(Json(EnrollResponse {
                name,
                token,
                api: format!("https://{}", state.config.api_host),
                server: format!("wss://{}", state.config.tunnel_host),
            }))
        }
        None => Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid_code", "invalid, used, or expired login code")),
    }
}

// ---------------------------------------------------------------- services

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateServiceRequest {
    /// 1..=64 characters: letters, digits, `.`, `_`, `-`.
    pub name: String,
    /// Live tunnels this service may own at once (1..=10000).
    pub max_tunnels: u32,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceTokenResponse {
    pub name: String,
    /// Service token (`tnsvc_…`), shown once; only its hash is stored. Use it
    /// as the bearer token for `/v1/tunnels` and `/v1/access-links`.
    pub token: String,
    /// `https://<api host>`
    pub api: String,
    /// `wss://<tunnel host>`
    pub server: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceView {
    pub name: String,
    pub max_tunnels: u32,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// Unexpired tunnels this service owns.
    pub tunnels: i64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceList {
    pub services: Vec<ServiceView>,
    /// Pass as `cursor` to fetch the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchServiceRequest {
    /// New live-tunnel quota (1..=10000). Tunnels above a lowered quota keep
    /// running; new ones are refused until the count is below it.
    pub max_tunnels: u32,
}

impl From<ServiceRow> for ServiceView {
    fn from(s: ServiceRow) -> Self {
        Self {
            name: s.name,
            max_tunnels: s.max_tunnels,
            created_at: s.created_at,
            last_used_at: s.last_used_at,
            tunnels: s.tunnels,
        }
    }
}

impl From<services::Error> for ApiError {
    fn from(e: services::Error) -> Self {
        match e {
            services::Error::Invalid(m) => ApiError::validation(m),
            services::Error::Taken => ApiError::new(
                StatusCode::CONFLICT,
                "service_exists",
                "a service with this name exists; delete it or rotate its token",
            ),
            services::Error::NotFound => ApiError::not_found("service"),
            services::Error::Other(e) => ApiError::internal(e),
        }
    }
}

fn service_token_response(state: &AppState, name: String, token: String) -> ServiceTokenResponse {
    ServiceTokenResponse {
        name,
        token,
        api: format!("https://{}", state.config.api_host),
        server: format!("wss://{}", state.config.tunnel_host),
    }
}

#[utoipa::path(
    post,
    path = "/v1/services",
    request_body = CreateServiceRequest,
    responses(
        (status = 201, body = ServiceTokenResponse),
        (status = 401, body = ErrorBody),
        (status = 409, body = ErrorBody),
        (status = 422, body = ErrorBody),
    )
)]
async fn create_service(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    ApiJson(req): ApiJson<CreateServiceRequest>,
) -> ApiResult<(StatusCode, Json<ServiceTokenResponse>)> {
    let token = services::new_token();
    let row = services::add(&state.db, &req.name, req.max_tunnels, &token).await?;
    tracing::info!(service = %row.name, max_tunnels = row.max_tunnels, "service created");
    Ok((StatusCode::CREATED, Json(service_token_response(&state, row.name, token))))
}

#[utoipa::path(
    get, path = "/v1/services",
    params(
        ("limit" = Option<u32>, Query, description = "Page size (default 100)", minimum = 1, maximum = 500),
        ("cursor" = Option<String>, Query, description = "Opaque next_cursor returned by the previous page"),
    ),
    responses((status = 200, body = ServiceList), (status = 401, body = ErrorBody), (status = 422, body = ErrorBody))
)]
async fn list_services(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    query: Result<Query<Pagination>, QueryRejection>,
) -> ApiResult<Json<ServiceList>> {
    let (limit, cursor) = pagination(query, true)?;
    let mut rows = state.db.list_services(cursor, Some(limit)).await?;
    let has_more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = if has_more { rows.last().map(|row| row.name.clone()) } else { None };
    Ok(Json(ServiceList { services: rows.into_iter().map(ServiceView::from).collect(), next_cursor }))
}

#[utoipa::path(
    patch,
    path = "/v1/services/{name}",
    params(("name" = String, Path, description = "Service name")),
    request_body = PatchServiceRequest,
    responses(
        (status = 200, body = ServiceView),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
        (status = 422, body = ErrorBody),
    )
)]
async fn patch_service(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path(name): Path<String>,
    ApiJson(req): ApiJson<PatchServiceRequest>,
) -> ApiResult<Json<ServiceView>> {
    services::set_quota(&state.db, &name, req.max_tunnels).await?;
    tracing::info!(service = %name, max_tunnels = req.max_tunnels, "service quota changed");
    let row = state
        .db
        .list_services(None, None)
        .await?
        .into_iter()
        .find(|s| s.name == name)
        .ok_or_else(|| ApiError::not_found("service"))?;
    Ok(Json(row.into()))
}

#[utoipa::path(
    post,
    path = "/v1/services/{name}/token",
    params(("name" = String, Path, description = "Service name")),
    responses(
        (status = 200, body = ServiceTokenResponse, description = "New token; the old one stops working at once"),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
async fn rotate_service_token(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path(name): Path<String>,
) -> ApiResult<Json<ServiceTokenResponse>> {
    let token = services::new_token();
    services::rotate(&state.db, &name, &token).await?;
    tracing::info!(service = %name, "service token rotated");
    Ok(Json(service_token_response(&state, name, token)))
}

#[utoipa::path(
    delete,
    path = "/v1/services/{name}",
    params(("name" = String, Path, description = "Service name")),
    responses(
        (status = 204, description = "Deleted; its token stops working and its tunnels close"),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
async fn delete_service(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    let tunnels = state.db.delete_service(name.clone()).await?.ok_or_else(|| ApiError::not_found("service"))?;
    for id in &tunnels {
        state.delete_tunnel(id, CloseReason::Deleted).await?;
    }
    tracing::info!(service = %name, tunnels = tunnels.len(), "service deleted");
    Ok(StatusCode::NO_CONTENT)
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
    let unflushed = crate::traffic::unflushed(state, &row.id);
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
        last_seen_at: row.last_seen_at,
        bytes_in: row.bytes_in.max(0) as u64 + unflushed.0,
        bytes_out: row.bytes_out.max(0) as u64 + unflushed.1,
        traffic_limited: row.user_id.as_deref().is_some_and(|u| state.traffic.user_blocked(u)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn access_patch_defers_omitted_password_to_transaction() {
        let current = Access {
            mode: AccessMode::Password,
            password_user: Some("ann".into()),
            password_hash: Some("test-hash".into()),
        };
        let access = build_access(
            AccessRequest { mode: AccessMode::Password, username: Some("beth".into()), password: None },
            Some(&current),
        )
        .await
        .unwrap();
        assert_eq!(access.password_user.as_deref(), Some("beth"));
        assert!(access.password_hash.is_none(), "a partial PATCH must not carry an earlier hash");
        assert!(
            build_access(
                AccessRequest { mode: AccessMode::Password, username: Some("ann".into()), password: None },
                None,
            )
            .await
            .is_err(),
            "creation still requires a password"
        );
    }

    const ADMIN_CREDENTIAL: &str = "tnadm_public-test-fixture";
    const CLIENT_CREDENTIAL: &str = "tncli_public-test-fixture";
    const HEALTH_CREDENTIAL: &str = "public-health-test-fixture";

    fn test_state(health: bool, quota: u32) -> Arc<AppState> {
        let mut config: crate::config::Config = serde_json::from_value(serde_json::json!({
            "preview_zone": "previews.example.com", "api_host": "api.example.com",
            "tunnel_host": "tunnel.example.com", "turn_host": "turn.example.com",
            "admin_token_hash": tokens::hash_token(ADMIN_CREDENTIAL),
            "acme": {"email": "test@example.com"},
            "dns": {"provider": "cloudflare", "zone": "example.com"}
        }))
        .unwrap();
        config.health_token_hash = health.then(|| tokens::hash_token(HEALTH_CREDENTIAL));
        config.limits.max_tunnels_per_client = quota;
        let db = crate::db::Db::open(std::path::Path::new(":memory:")).unwrap();
        let certs = crate::tls::CertStore::new(std::env::temp_dir().join("tunnel-api-tests").join("certs"));
        AppState::new(config, db, certs)
    }

    async fn request(
        state: &Arc<AppState>,
        method: &str,
        uri: &str,
        credential: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(credential) = credential {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {credential}"));
        }
        let body = if let Some(body) = body {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            axum::body::Body::from(body.to_string())
        } else {
            axum::body::Body::empty()
        };
        let response = build_router().with_state(state.clone()).oneshot(builder.body(body).unwrap()).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = if bytes.is_empty() { serde_json::Value::Null } else { serde_json::from_slice(&bytes).unwrap() };
        (status, body)
    }

    async fn enroll_test_client(state: &Arc<AppState>, id: &str, name: &str) {
        state.db.insert_test_user("utest", "tester", Role::Member).await;
        state
            .db
            .create_client(id.into(), name.into(), "utest".into(), format!("code-{id}"), now() + 600, None)
            .await
            .unwrap()
            .unwrap();
        state.db.enroll_client(format!("code-{id}"), tokens::hash_token(CLIENT_CREDENTIAL)).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn open_health_omits_version_even_with_admin_token() {
        let state = test_state(false, 20);
        for credential in [None, Some(ADMIN_CREDENTIAL), Some(HEALTH_CREDENTIAL)] {
            let (status, body) = request(&state, "GET", "/healthz", credential, None).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE); // No test certificate loaded.
            assert_eq!(body["database"], true);
            assert!(body.get("version").is_none());
        }
    }

    #[tokio::test]
    async fn protected_health_accepts_only_health_token_in_header_or_query() {
        let state = test_state(true, 20);
        for (uri, credential) in
            [("/healthz".to_string(), Some(HEALTH_CREDENTIAL)), (format!("/healthz?token={HEALTH_CREDENTIAL}"), None)]
        {
            let (status, body) = request(&state, "GET", &uri, credential, None).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        }
        for (uri, credential) in [
            ("/healthz".to_string(), None),
            ("/healthz".to_string(), Some(ADMIN_CREDENTIAL)),
            (format!("/healthz?token={ADMIN_CREDENTIAL}"), None),
            ("/healthz".to_string(), Some("wrong")),
            ("/healthz?token=wrong".to_string(), None),
        ] {
            let (status, body) = request(&state, "GET", &uri, credential, None).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(body["error"]["code"], "not_found");
        }
    }

    #[tokio::test]
    async fn client_tunnel_quota_returns_429_and_admin_is_unlimited() {
        let state = test_state(false, 1);
        enroll_test_client(&state, "c1", "one").await;
        for expected in [StatusCode::CREATED, StatusCode::TOO_MANY_REQUESTS] {
            let (status, body) = request(
                &state,
                "POST",
                "/v1/tunnels",
                Some(CLIENT_CREDENTIAL),
                Some(serde_json::json!({"ttl_s": 600})),
            )
            .await;
            assert_eq!(status, expected);
            if status == StatusCode::TOO_MANY_REQUESTS {
                assert_eq!(body["error"]["code"], "tunnel_quota");
            }
        }
        for _ in 0..2 {
            let (status, _) =
                request(&state, "POST", "/v1/tunnels", Some(ADMIN_CREDENTIAL), Some(serde_json::json!({"ttl_s": 600})))
                    .await;
            assert_eq!(status, StatusCode::CREATED);
        }
    }

    #[tokio::test]
    async fn tunnel_and_client_lists_have_two_keyset_pages() {
        let state = test_state(false, 20);
        enroll_test_client(&state, "c1", "one").await;
        for (id, name) in [("c2", "two"), ("c3", "three")] {
            state.db.insert_test_user("utest", "tester", Role::Member).await;
            state
                .db
                .create_client(id.into(), name.into(), "utest".into(), format!("code-{id}"), now() + 600, None)
                .await
                .unwrap()
                .unwrap();
        }
        for _ in 0..3 {
            assert_eq!(
                request(
                    &state,
                    "POST",
                    "/v1/tunnels",
                    Some(CLIENT_CREDENTIAL),
                    Some(serde_json::json!({"ttl_s": 600}))
                )
                .await
                .0,
                StatusCode::CREATED
            );
        }
        assert_eq!(
            request(&state, "POST", "/v1/tunnels", Some(ADMIN_CREDENTIAL), Some(serde_json::json!({"ttl_s": 600})))
                .await
                .0,
            StatusCode::CREATED
        );
        for (path, field, key, credential, total) in [
            ("/v1/tunnels", "tunnels", "id", CLIENT_CREDENTIAL, 3),
            ("/v1/tunnels", "tunnels", "id", ADMIN_CREDENTIAL, 4),
            ("/v1/clients", "clients", "name", ADMIN_CREDENTIAL, 3),
        ] {
            let (status, first) = request(&state, "GET", &format!("{path}?limit=2"), Some(credential), None).await;
            assert_eq!(status, StatusCode::OK);
            let rows = first[field].as_array().unwrap();
            assert_eq!(rows.len(), 2);
            let cursor = first["next_cursor"].as_str().unwrap();
            assert_eq!(cursor, rows[1][key].as_str().unwrap());
            let (status, second) =
                request(&state, "GET", &format!("{path}?limit=2&cursor={cursor}"), Some(credential), None).await;
            assert_eq!(status, StatusCode::OK);
            let remaining = second[field].as_array().unwrap();
            assert_eq!(remaining.len(), total - 2);
            assert!(remaining[0][key].as_str().unwrap() > cursor);
            assert!(second.get("next_cursor").is_none());
        }
    }

    #[tokio::test]
    async fn list_default_page_size_is_100() {
        let state = test_state(false, 20);
        state
            .db
            .call(|c| {
                let tx = c.transaction()?;
                tx.execute(
                    "INSERT INTO users (id, username, password_hash, role, max_tunnels, max_clients, created_at)
                     VALUES ('utest', 'tester', 'x', 'member', 1000, 1000, 0)",
                    [],
                )?;
                for i in 0..101 {
                    tx.execute(
                        "INSERT INTO clients (id, name, created_at, user_id) VALUES (?1, ?1, ?2, 'utest')",
                        rusqlite::params![format!("client-{i:03}"), now()],
                    )?;
                    tx.execute(
                    "INSERT INTO tunnels (id, token_hash, max_ports, host_header, inject_ice, created_at, expires_at)
                     VALUES (?1, ?1, 8, 'rewrite', 0, ?2, ?3)",
                    rusqlite::params![tokens::random_tunnel_id(), now(), now() + 600],
                )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .unwrap();
        for (path, field) in [("/v1/tunnels", "tunnels"), ("/v1/clients", "clients")] {
            let (status, first) = request(&state, "GET", path, Some(ADMIN_CREDENTIAL), None).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(first[field].as_array().unwrap().len(), 100);
            let cursor = first["next_cursor"].as_str().unwrap();
            let (_, last) =
                request(&state, "GET", &format!("{path}?cursor={cursor}"), Some(ADMIN_CREDENTIAL), None).await;
            assert_eq!(last[field].as_array().unwrap().len(), 1);
            assert!(last.get("next_cursor").is_none());
        }
    }

    #[tokio::test]
    async fn pagination_rejects_bad_cursors_and_limits_with_422() {
        let state = test_state(false, 20);
        for path in ["/v1/tunnels", "/v1/clients"] {
            for query in ["cursor=bad!", "cursor=", "limit=0", "limit=501", "limit=-1", "limit=abc"] {
                let (status, body) =
                    request(&state, "GET", &format!("{path}?{query}"), Some(ADMIN_CREDENTIAL), None).await;
                assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
                assert_eq!(body["error"]["code"], "validation");
            }
            for query in ["", "?limit=1", "?limit=500"] {
                let (status, _) = request(&state, "GET", &format!("{path}{query}"), Some(ADMIN_CREDENTIAL), None).await;
                assert_eq!(status, StatusCode::OK);
            }
        }
    }

    #[tokio::test]
    async fn access_link_response_keeps_full_url_without_url_path() {
        let state = test_state(false, 20);
        let (_, tunnel) =
            request(&state, "POST", "/v1/tunnels", Some(ADMIN_CREDENTIAL), Some(serde_json::json!({"ttl_s": 600})))
                .await;
        let id = tunnel["id"].as_str().unwrap();
        let (status, link) = request(
            &state,
            "POST",
            &format!("/v1/tunnels/{id}/access-links"),
            Some(ADMIN_CREDENTIAL),
            Some(serde_json::json!({"ttl_s": 60})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(link["url"].as_str().unwrap().starts_with("https://previews.example.com/__access/"));
        assert!(link["id"].is_string());
        assert!(link["expires_at"].is_i64());
        assert!(link.get("url_path").is_none());
    }

    #[test]
    fn openapi_keeps_management_paths() {
        let doc = serde_json::to_value(ApiDoc::openapi()).unwrap();
        assert_eq!(doc["openapi"], "3.1.0");
        let expected = [
            ("/healthz", vec!["get"]),
            ("/v1/tunnels", vec!["get", "post"]),
            ("/v1/tunnels/{id}", vec!["get", "patch", "delete"]),
            ("/v1/tunnels/{id}/access-links", vec!["get", "post"]),
            ("/v1/access-links/{id}", vec!["delete"]),
            ("/v1/tunnels/{id}/turn-credentials", vec!["post"]),
            ("/v1/clients", vec!["get", "post"]),
            ("/v1/clients/{name}", vec!["patch", "delete"]),
            ("/v1/clients/enroll", vec!["post"]),
            ("/v1/tunnels/{id}/token", vec!["post"]),
            ("/v1/services", vec!["get", "post"]),
            ("/v1/services/{name}", vec!["patch", "delete"]),
            ("/v1/services/{name}/token", vec!["post"]),
            ("/v1/server", vec!["get"]),
            ("/v1/device/code", vec!["post"]),
            ("/v1/device/token", vec!["post"]),
        ];
        assert_eq!(doc["paths"].as_object().unwrap().len(), expected.len());
        for (path, methods) in expected {
            for method in methods {
                assert!(doc["paths"][path][method].is_object(), "missing {method} {path}");
            }
        }
        assert_eq!(doc["components"]["securitySchemes"]["admin"]["scheme"], "bearer");
        assert!(doc["components"]["schemas"]["CreateTunnelRequest"].is_object());
        assert!(doc["components"]["schemas"]["AccessLinkResponse"]["properties"].get("url_path").is_none());
        assert!(doc["components"]["schemas"]["Health"]["required"].as_array().unwrap().iter().all(|v| v != "version"));
        assert!(doc["paths"]["/v1/tunnels"]["post"]["responses"]["429"].is_object());
        assert!(doc["paths"]["/v1/tunnels"]["post"]["responses"]["403"].is_object());
        assert!(
            doc["paths"]["/v1/tunnels"]["get"]["parameters"].as_array().unwrap().iter().any(|p| p["name"] == "label")
        );
        for path in ["/v1/tunnels", "/v1/clients", "/v1/services"] {
            let params = doc["paths"][path]["get"]["parameters"].as_array().unwrap();
            assert!(
                params
                    .iter()
                    .any(|p| p["name"] == "limit" && p["schema"]["minimum"] == 1 && p["schema"]["maximum"] == 500)
            );
            assert!(params.iter().any(|p| p["name"] == "cursor"));
            assert!(doc["paths"][path]["get"]["responses"]["422"].is_object());
        }
    }

    async fn add_service(state: &Arc<AppState>, name: &str, max_tunnels: u32) -> String {
        let (status, body) = request(
            state,
            "POST",
            "/v1/services",
            Some(ADMIN_CREDENTIAL),
            Some(serde_json::json!({"name": name, "max_tunnels": max_tunnels})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["name"], name);
        assert_eq!(body["api"], "https://api.example.com");
        assert_eq!(body["server"], "wss://tunnel.example.com");
        let token = body["token"].as_str().unwrap().to_string();
        assert!(token.starts_with(SERVICE_TOKEN_PREFIX));
        token
    }

    async fn create(
        state: &Arc<AppState>,
        credential: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        request(state, "POST", "/v1/tunnels", Some(credential), Some(body)).await
    }

    #[tokio::test]
    async fn service_owns_only_its_tunnels_within_its_quota() {
        let state = test_state(false, 1);
        enroll_test_client(&state, "c1", "one").await;
        let svc = add_service(&state, "wssp", 3).await;

        // Its own quota, not the client default of 1.
        for expected in [StatusCode::CREATED, StatusCode::CREATED, StatusCode::CREATED, StatusCode::TOO_MANY_REQUESTS] {
            let (status, body) = create(&state, &svc, serde_json::json!({"ttl_s": 600, "label": "sbx"})).await;
            assert_eq!(status, expected);
            if status == StatusCode::TOO_MANY_REQUESTS {
                assert_eq!(body["error"]["code"], "tunnel_quota");
            }
        }
        let (status, mine) = request(&state, "GET", "/v1/tunnels", Some(&svc), None).await;
        assert_eq!(status, StatusCode::OK);
        let mine: Vec<String> =
            mine["tunnels"].as_array().unwrap().iter().map(|t| t["id"].as_str().unwrap().to_string()).collect();
        assert_eq!(mine.len(), 3);

        // Other owners' tunnels and links are invisible to the service, and its tunnels to them.
        let (_, client_tunnel) = create(&state, CLIENT_CREDENTIAL, serde_json::json!({"ttl_s": 600})).await;
        let (_, admin_tunnel) = create(&state, ADMIN_CREDENTIAL, serde_json::json!({"ttl_s": 600})).await;
        for other in [&client_tunnel, &admin_tunnel] {
            let id = other["id"].as_str().unwrap();
            let (status, link) = request(
                &state,
                "POST",
                &format!("/v1/tunnels/{id}/access-links"),
                Some(ADMIN_CREDENTIAL),
                Some(serde_json::json!({"ttl_s": 60})),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            let link = link["id"].as_str().unwrap();
            for (method, uri) in [
                ("GET", format!("/v1/tunnels/{id}")),
                ("PATCH", format!("/v1/tunnels/{id}")),
                ("DELETE", format!("/v1/tunnels/{id}")),
                ("POST", format!("/v1/tunnels/{id}/token")),
                ("POST", format!("/v1/tunnels/{id}/access-links")),
                ("DELETE", format!("/v1/access-links/{link}")),
            ] {
                let body = (method != "DELETE" && !uri.ends_with("/token")).then(|| serde_json::json!({"ttl_s": 60}));
                let (status, _) = request(&state, method, &uri, Some(&svc), body).await;
                assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
            }
            assert!(state.db.get_tunnel(id.to_string()).await.unwrap().is_some(), "service deleted {id}");
        }
        let (_, client_list) = request(&state, "GET", "/v1/tunnels", Some(CLIENT_CREDENTIAL), None).await;
        assert_eq!(client_list["tunnels"].as_array().unwrap().len(), 1);

        // No client or service management.
        for (method, uri) in [
            ("GET", "/v1/clients"),
            ("POST", "/v1/clients"),
            ("DELETE", "/v1/clients/one"),
            ("PATCH", "/v1/clients/one"),
            ("GET", "/v1/services"),
            ("POST", "/v1/services"),
            ("PATCH", "/v1/services/wssp"),
            ("POST", "/v1/services/wssp/token"),
            ("DELETE", "/v1/services/wssp"),
            ("GET", "/v1/openapi.json"),
        ] {
            let body = matches!(method, "POST" | "PATCH").then(|| serde_json::json!({"name": "x", "max_tunnels": 9}));
            let (status, _) = request(&state, method, uri, Some(&svc), body).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        }

        // The admin raises the quota; the listing shows it and the usage.
        let (status, view) = request(
            &state,
            "PATCH",
            "/v1/services/wssp",
            Some(ADMIN_CREDENTIAL),
            Some(serde_json::json!({"max_tunnels": 4})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["max_tunnels"], 4);
        assert_eq!(view["tunnels"], 3);
        assert_eq!(create(&state, &svc, serde_json::json!({"ttl_s": 600})).await.0, StatusCode::CREATED);
        let (_, list) = request(&state, "GET", "/v1/services", Some(ADMIN_CREDENTIAL), None).await;
        assert_eq!(list["services"][0]["name"], "wssp");
        assert_eq!(list["services"][0]["tunnels"], 4);
        assert!(list["services"][0]["last_used_at"].is_i64());

        // Own tunnels: delete works.
        let (status, _) = request(&state, "DELETE", &format!("/v1/tunnels/{}", mine[0]), Some(&svc), None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Deleting the service ends its tunnels and its token.
        let (status, _) = request(&state, "DELETE", "/v1/services/wssp", Some(ADMIN_CREDENTIAL), None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(request(&state, "GET", "/v1/tunnels", Some(&svc), None).await.0, StatusCode::UNAUTHORIZED);
        for id in &mine[1..] {
            assert!(state.db.get_tunnel(id.clone()).await.unwrap().is_none(), "{id} survived its service");
        }
        assert!(state.db.get_tunnel(client_tunnel["id"].as_str().unwrap().into()).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn service_admin_validation_and_token_rotation() {
        let state = test_state(false, 20);
        for body in [
            serde_json::json!({"name": "bad name", "max_tunnels": 5}),
            serde_json::json!({"name": "ok", "max_tunnels": 0}),
            serde_json::json!({"name": "ok", "max_tunnels": 10_001}),
            serde_json::json!({"name": "ok"}),
        ] {
            let (status, _) = request(&state, "POST", "/v1/services", Some(ADMIN_CREDENTIAL), Some(body)).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        }
        let old = add_service(&state, "wssp", 5).await;
        let (status, body) = request(
            &state,
            "POST",
            "/v1/services",
            Some(ADMIN_CREDENTIAL),
            Some(serde_json::json!({"name": "wssp", "max_tunnels": 5})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["code"], "service_exists");
        let (status, body) = request(&state, "POST", "/v1/services/wssp/token", Some(ADMIN_CREDENTIAL), None).await;
        assert_eq!(status, StatusCode::OK);
        let new = body["token"].as_str().unwrap();
        assert_ne!(new, old);
        assert_eq!(request(&state, "GET", "/v1/tunnels", Some(&old), None).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(request(&state, "GET", "/v1/tunnels", Some(new), None).await.0, StatusCode::OK);
        for (method, uri) in [("POST", "/v1/services/nope/token"), ("DELETE", "/v1/services/nope")] {
            assert_eq!(request(&state, method, uri, Some(ADMIN_CREDENTIAL), None).await.0, StatusCode::NOT_FOUND);
        }
        let (status, _) = request(
            &state,
            "PATCH",
            "/v1/services/nope",
            Some(ADMIN_CREDENTIAL),
            Some(serde_json::json!({"max_tunnels": 3})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn public_previews_need_the_admin_unless_allowed() {
        let state = test_state(false, 20);
        enroll_test_client(&state, "c1", "one").await;
        let svc = add_service(&state, "wssp", 5).await;
        let public = serde_json::json!({"ttl_s": 600, "access": {"mode": "public"}});
        for credential in [CLIENT_CREDENTIAL, svc.as_str()] {
            let (status, body) = create(&state, credential, public.clone()).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["error"]["code"], "public_not_allowed");
            // Links and password mode stay available.
            assert_eq!(create(&state, credential, serde_json::json!({"ttl_s": 600})).await.0, StatusCode::CREATED);
            let (status, created) = create(
                &state,
                credential,
                serde_json::json!({"ttl_s": 600, "access": {"mode": "password", "username": "u", "password": "long-enough-pw"}}),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            let id = created["id"].as_str().unwrap();
            let (status, body) = request(
                &state,
                "PATCH",
                &format!("/v1/tunnels/{id}"),
                Some(credential),
                Some(serde_json::json!({"access": {"mode": "public"}})),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["error"]["code"], "public_not_allowed");
        }
        assert_eq!(create(&state, ADMIN_CREDENTIAL, public.clone()).await.0, StatusCode::CREATED);

        // A tunnel that is already public (made while the setting was on) stays editable.
        let (status, created) = {
            let mut config = state.config.clone();
            config.limits.allow_public_for_clients = true;
            let allowed = AppState::new(config, state.db.clone(), state.certs.clone());
            create(&allowed, &svc, public.clone()).await
        };
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"].as_str().unwrap();
        let (status, _) = request(
            &state,
            "PATCH",
            &format!("/v1/tunnels/{id}"),
            Some(&svc),
            Some(serde_json::json!({"label": "x", "access": {"mode": "public"}})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn tunnel_list_filters_by_exact_label_within_owner() {
        let state = test_state(false, 20);
        let svc = add_service(&state, "wssp", 10).await;
        for (credential, label) in
            [(svc.as_str(), "sbx-1"), (svc.as_str(), "sbx-1"), (svc.as_str(), "sbx-10"), (ADMIN_CREDENTIAL, "sbx-1")]
        {
            let (status, _) = create(&state, credential, serde_json::json!({"ttl_s": 600, "label": label})).await;
            assert_eq!(status, StatusCode::CREATED);
        }
        for (credential, label, n) in [
            (svc.as_str(), "sbx-1", 2),
            (svc.as_str(), "sbx-10", 1),
            (svc.as_str(), "sbx", 0),
            (ADMIN_CREDENTIAL, "sbx-1", 3),
        ] {
            let (status, body) =
                request(&state, "GET", &format!("/v1/tunnels?label={label}"), Some(credential), None).await;
            assert_eq!(status, StatusCode::OK);
            let rows = body["tunnels"].as_array().unwrap();
            assert_eq!(rows.len(), n, "{label}");
            assert!(rows.iter().all(|t| t["label"] == label));
        }
        // A misspelt filter must not silently list everything.
        let (status, _) = request(&state, "GET", "/v1/tunnels?labels=sbx-1", Some(&svc), None).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    type Live = (
        Arc<crate::registry::LiveTunnel>,
        tokio::sync::mpsc::Receiver<tunnel_protocol::ServerMsg>,
        tunnel_protocol::mux::Session,
    );

    fn live_tunnel(id: &str, token_hash: String) -> Live {
        let (transport, _peer) = tokio::io::duplex(64);
        let session = tunnel_protocol::mux::Session::new_server(transport);
        let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::channel(1);
        let live = Arc::new(crate::registry::LiveTunnel {
            conn_id: 1,
            tunnel_id: id.into(),
            control: session.control(),
            ports: Default::default(),
            ctrl_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            connected_at: now(),
            streams: Default::default(),
            pool: Default::default(),
            token_hash,
        });
        (live, ctrl_rx, session)
    }

    fn closed_as(rx: &mut tokio::sync::mpsc::Receiver<tunnel_protocol::ServerMsg>) -> Option<CloseReason> {
        match rx.try_recv() {
            Ok(tunnel_protocol::ServerMsg::Close { reason }) => Some(reason),
            _ => None,
        }
    }

    #[tokio::test]
    async fn tunnel_token_rotation_replaces_the_old_host() {
        let state = test_state(false, 20);
        let svc = add_service(&state, "wssp", 10).await;
        let (_, created) = create(&state, &svc, serde_json::json!({"ttl_s": 600})).await;
        let id = created["id"].as_str().unwrap().to_string();
        let old = created["tunnel_token"].as_str().unwrap().to_string();
        let (live, mut live_rx, _session) = live_tunnel(&id, tokens::hash_token(&old));
        state.registry.insert(live.clone());

        let (status, body) = request(&state, "POST", &format!("/v1/tunnels/{id}/token"), Some(&svc), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], id);
        let new = body["tunnel_token"].as_str().unwrap();
        assert!(new.starts_with(TUNNEL_TOKEN_PREFIX));
        assert_ne!(new, old);
        assert_eq!(closed_as(&mut live_rx), Some(CloseReason::Replaced), "the old host's connection must close");
        assert!(state.db.find_tunnel_by_token_hash(tokens::hash_token(&old)).await.unwrap().is_none());
        let row = state.db.find_tunnel_by_token_hash(tokens::hash_token(new)).await.unwrap().unwrap();
        assert_eq!(row.id, id);

        // A host already holding the newest token is left alone.
        let (status, body) = request(&state, "POST", &format!("/v1/tunnels/{id}/token"), Some(&svc), None).await;
        assert_eq!(status, StatusCode::OK);
        let newest = body["tunnel_token"].as_str().unwrap();
        let (current, mut current_rx, _session2) = live_tunnel(&id, tokens::hash_token(newest));
        state.registry.insert(current.clone());
        crate::control::recheck(&state, &current).await;
        assert_eq!(closed_as(&mut current_rx), None);
        // A connection that authenticated with a superseded token closes on recheck.
        let (stale, mut stale_rx, _session3) = live_tunnel(&id, tokens::hash_token(new));
        crate::control::recheck(&state, &stale).await;
        assert_eq!(closed_as(&mut stale_rx), Some(CloseReason::Replaced));

        // Admin may rotate any tunnel; an expired one cannot be rotated.
        assert_eq!(
            request(&state, "POST", &format!("/v1/tunnels/{id}/token"), Some(ADMIN_CREDENTIAL), None).await.0,
            StatusCode::OK
        );
        state
            .db
            .call({
                let id = id.clone();
                move |c| Ok(c.execute("UPDATE tunnels SET expires_at = 1 WHERE id = ?1", rusqlite::params![id])?)
            })
            .await
            .unwrap();
        let (status, body) = request(&state, "POST", &format!("/v1/tunnels/{id}/token"), Some(&svc), None).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["code"], "tunnel_expired");
    }

    #[tokio::test]
    async fn stale_handshake_cannot_evict_the_host_with_the_new_token() {
        let state = test_state(false, 20);
        let svc = add_service(&state, "wssp", 10).await;
        let (_, created) = create(&state, &svc, serde_json::json!({"ttl_s": 600})).await;
        let id = created["id"].as_str().unwrap().to_string();
        let old = created["tunnel_token"].as_str().unwrap().to_string();
        let (_, body) = request(&state, "POST", &format!("/v1/tunnels/{id}/token"), Some(&svc), None).await;
        let new = body["tunnel_token"].as_str().unwrap().to_string();

        let (host, mut host_rx, _s1) = live_tunnel(&id, tokens::hash_token(&new));
        assert_eq!(crate::control::register(&state, &host).await.unwrap(), None);
        // A connection that authenticated with the old token before the
        // rotation finishes its handshake now.
        let (stale, mut stale_rx, _s2) = live_tunnel(&id, tokens::hash_token(&old));
        let mut stale = stale;
        Arc::get_mut(&mut stale).unwrap().conn_id = 2;
        assert_eq!(crate::control::register(&state, &stale).await.unwrap(), Some(CloseReason::Replaced));
        assert_eq!(closed_as(&mut stale_rx), None, "the session loop sends the reason, not register");
        assert_eq!(closed_as(&mut host_rx), None, "the current host must stay connected");
        assert_eq!(state.registry.get(&id).unwrap().conn_id, host.conn_id);
    }

    #[tokio::test]
    async fn rotation_waits_for_registration_in_progress() {
        let state = test_state(false, 20);
        let svc = add_service(&state, "wssp", 10).await;
        let (_, created) = create(&state, &svc, serde_json::json!({"ttl_s": 600})).await;
        let id = created["id"].as_str().unwrap().to_string();
        let held = state.token_lock(&id).lock().await;
        let rotation = tokio::spawn({
            let state = state.clone();
            let uri = format!("/v1/tunnels/{id}/token");
            async move { request(&state, "POST", &uri, Some(&svc), None).await.0 }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!rotation.is_finished(), "rotation must not interleave with a registration");
        assert!(
            state
                .db
                .find_tunnel_by_token_hash(tokens::hash_token(created["tunnel_token"].as_str().unwrap()))
                .await
                .unwrap()
                .is_some()
        );
        drop(held);
        assert_eq!(rotation.await.unwrap(), StatusCode::OK);
    }

    #[tokio::test]
    async fn dropped_rotation_request_still_completes_under_the_lock() {
        let state = test_state(false, 20);
        let svc = add_service(&state, "wssp", 10).await;
        let (_, created) = create(&state, &svc, serde_json::json!({"ttl_s": 600})).await;
        let id = created["id"].as_str().unwrap().to_string();
        let old = created["tunnel_token"].as_str().unwrap().to_string();
        let (host, mut host_rx, _s) = live_tunnel(&id, tokens::hash_token(&old));
        state.registry.insert(host);

        let held = state.token_lock(&id).lock().await;
        let request_task = tokio::spawn({
            let state = state.clone();
            let uri = format!("/v1/tunnels/{id}/token");
            async move { request(&state, "POST", &uri, Some(&svc), None).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        request_task.abort(); // The client went away mid-rotation.
        let _ = request_task.await;
        drop(held);
        // The detached rotation finishes on its own: the old host is told and the old token is gone.
        let reason = tokio::time::timeout(std::time::Duration::from_secs(5), host_rx.recv()).await.unwrap();
        assert_eq!(reason, Some(tunnel_protocol::ServerMsg::Close { reason: CloseReason::Replaced }));
        assert!(state.db.find_tunnel_by_token_hash(tokens::hash_token(&old)).await.unwrap().is_none());
    }
}
