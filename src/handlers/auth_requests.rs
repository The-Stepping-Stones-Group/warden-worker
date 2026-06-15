use axum::{
    extract::{Extension, Path, Query, State},
    http::HeaderMap,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::{
    auth::Claims,
    client_context::{request_device_type_from_headers, request_ip_from_headers},
    db,
    error::AppError,
    models::{auth_request::AuthRequest, device::Device, user::User},
    notifications, BaseUrl,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAuthRequest {
    access_code: String,
    device_identifier: String,
    email: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAuthRequest {
    device_identifier: String,
    key: String,
    master_password_hash: Option<String>,
    request_approved: bool,
}

#[derive(Debug, Deserialize)]
pub struct AuthRequestResponseQuery {
    code: String,
}

fn bad_request() -> AppError {
    AppError::BadRequest("AuthRequest doesn't exist".to_string())
}

fn auth_request_rate_limit_key(email: &str, device_identifier: &str, ip: &str) -> String {
    format!(
        "auth-request:{}:{}:{}",
        email.trim().to_lowercase(),
        device_identifier.trim(),
        ip
    )
}

async fn enforce_rate_limit(env: &Env, key: String) -> Result<(), AppError> {
    if let Ok(rate_limiter) = env.rate_limiter("LOGIN_RATE_LIMITER") {
        if let Ok(outcome) = rate_limiter.limit(key).await {
            if !outcome.success {
                return Err(AppError::TooManyRequests(
                    "Too many requests. Please try again later.".to_string(),
                ));
            }
        }
    }

    Ok(())
}

async fn find_user_by_id(db: &crate::db::Db, user_id: &str) -> Result<User, AppError> {
    let row: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(bad_request)?;

    serde_json::from_value(row).map_err(|_| AppError::Internal)
}

/// POST /api/auth-requests
#[worker::send]
pub async fn post_auth_request(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    headers: HeaderMap,
    Json(payload): Json<CreateAuthRequest>,
) -> Result<Json<Value>, AppError> {
    let request_ip = request_ip_from_headers(&headers);
    enforce_rate_limit(
        &env,
        auth_request_rate_limit_key(&payload.email, &payload.device_identifier, &request_ip),
    )
    .await?;

    let db = db::get_db(&env)?;
    let user = User::find_by_email(&db, &payload.email.to_lowercase())
        .await?
        .ok_or_else(bad_request)?;
    let request_device_type = request_device_type_from_headers(&headers);

    let device =
        Device::find_by_identifier_and_user(&db, &payload.device_identifier, &user.id).await?;
    let device = device.ok_or_else(bad_request)?;

    if device.r#type != request_device_type {
        return Err(bad_request());
    }

    let auth_request = AuthRequest::new(
        user.id.clone(),
        payload.device_identifier,
        request_device_type,
        request_ip,
        payload.access_code,
        payload.public_key,
    );
    auth_request.insert(&db).await?;

    let response = auth_request.to_json(&base_url);

    notifications::publish_auth_update(
        (*env).clone(),
        user.id,
        notifications::UpdateType::AuthRequest,
        auth_request.id,
        Some(auth_request.request_device_identifier),
    );

    Ok(Json(response))
}

/// GET /api/auth-requests
/// Now unused but not yet removed
#[worker::send]
pub async fn get_auth_requests(
    state: State<Arc<Env>>,
    base_url: Extension<BaseUrl>,
    claims: Claims,
) -> Result<Json<Value>, AppError> {
    get_auth_requests_pending(state, base_url, claims).await
}

/// GET /api/auth-requests/pending
#[worker::send]
pub async fn get_auth_requests_pending(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    claims: Claims,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let data = AuthRequest::list_pending_by_user(&db, &claims.sub).await?;
    Ok(Json(json!({
        "data": data.into_iter().map(|request| request.to_json(&base_url)).collect::<Vec<Value>>(),
        "continuationToken": null,
        "object": "list",
    })))
}

/// GET /api/auth-requests/{id}
#[worker::send]
pub async fn get_auth_request(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    claims: Claims,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let auth_request = AuthRequest::find_by_id_and_user(&db, &id, &claims.sub)
        .await?
        .ok_or_else(bad_request)?;

    Ok(Json(auth_request.to_json(&base_url)))
}

/// PUT /api/auth-requests/{id}
#[worker::send]
pub async fn put_auth_request(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    claims: Claims,
    Path(id): Path<String>,
    Json(payload): Json<UpdateAuthRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut auth_request = AuthRequest::find_by_id_and_user(&db, &id, &claims.sub)
        .await?
        .ok_or_else(bad_request)?;

    if claims.device != payload.device_identifier {
        return Err(bad_request());
    }

    if auth_request.approved.is_some() {
        return Err(AppError::BadRequest(
            "An authentication request with the same device already exists".to_string(),
        ));
    }
    if auth_request.is_expired() {
        return Err(bad_request());
    }

    auth_request.response_date = Some(db::now_string());

    if payload.request_approved {
        let provided_hash = payload
            .master_password_hash
            .as_deref()
            .ok_or_else(|| AppError::Unauthorized("Invalid password".to_string()))?;
        let user = find_user_by_id(&db, &claims.sub).await?;
        if !user.verify_master_password(provided_hash).await?.is_valid() {
            return Err(AppError::Unauthorized("Invalid password".to_string()));
        }

        auth_request.set_approved(true);
        auth_request.enc_key = Some(payload.key);
        auth_request.master_password_hash = Some(provided_hash.to_string());
        auth_request.response_device_id = Some(payload.device_identifier);
        auth_request.update(&db).await?;

        notifications::publish_anonymous_update(
            (*env).clone(),
            auth_request.id.clone(),
            auth_request.user_id.clone(),
            auth_request.id.clone(),
        );
        notifications::publish_auth_update(
            (*env).clone(),
            auth_request.user_id.clone(),
            notifications::UpdateType::AuthRequestResponse,
            auth_request.id.clone(),
            Some(claims.device),
        );
    } else {
        auth_request.delete(&db).await?;
    }

    Ok(Json(auth_request.to_json(&base_url)))
}

/// GET /api/auth-requests/{id}/response
#[worker::send]
pub async fn get_auth_request_response(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<AuthRequestResponseQuery>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let auth_request = AuthRequest::find_by_id(&db, &id)
        .await?
        .ok_or_else(bad_request)?;

    if !auth_request.can_return_response_material(
        request_device_type_from_headers(&headers),
        &request_ip_from_headers(&headers),
        &query.code,
    ) {
        return Err(bad_request());
    }

    Ok(Json(auth_request.to_json(&base_url)))
}
