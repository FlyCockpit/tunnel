//! `/v1/services`: API-only callers with their own tokens and quotas.

use super::*;

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

pub(super) fn service_token_response(state: &AppState, name: String, token: String) -> ServiceTokenResponse {
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
pub(super) async fn create_service(
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
pub(super) async fn list_services(
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
pub(super) async fn patch_service(
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
pub(super) async fn rotate_service_token(
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
pub(super) async fn delete_service(
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
