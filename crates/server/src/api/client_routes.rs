//! `/v1/clients`: machines enrolled with a login code or by an admin.

use super::*;

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
pub(super) async fn create_client(
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
        Err(clients::AddError::Quota { limit, .. }) => Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "client_quota",
            format!("this user's machine limit ({limit}) is reached; raise it in the web UI's Users page"),
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
pub(super) async fn list_clients(
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
pub(super) async fn delete_client(
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
pub(super) async fn rename_client(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path(name): Path<String>,
    ApiJson(req): ApiJson<RenameClientRequest>,
) -> ApiResult<Json<RenameClientRequest>> {
    clients::validate_new_name(&req.name).map_err(ApiError::validation)?;
    match state.db.rename_client(name.clone(), req.name.clone(), None).await? {
        Ok(()) => {}
        Err(crate::accounts::RenameError::Taken) => {
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
pub(super) async fn enroll_client(
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
