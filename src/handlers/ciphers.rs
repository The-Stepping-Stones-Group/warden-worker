use crate::d1_query;
use axum::extract::Path;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::{extract::State, Extension, Json};
use chrono::{DateTime, Utc};
use log; // Used for warning logs on parse failures
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeSet, sync::Arc};
use uuid::Uuid;
use worker::{wasm_bindgen::JsValue, Env};

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::handlers::attachments;
use crate::handlers::cipher_access::{
    ensure_cipher_delete, ensure_cipher_read, ensure_cipher_write, get_cipher_access_view,
    CipherAccessView,
};
use crate::models::cipher::{
    Cipher, CipherDBModel, CipherData, CipherRequestData, CreateCipherRequest, PartialCipherData,
};
use crate::models::organization::{is_org_admin_type, ORG_USER_STATUS_CONFIRMED};
use crate::models::user::{PasswordOrOtpData, User};
use crate::notifications::{self, CipherNotificationContext, CipherUpdateNotification, UpdateType};
use crate::BaseUrl;

/// A wrapper for raw JSON strings that implements IntoResponse.
/// Use this to return pre-built JSON without re-parsing/re-serializing.
pub struct RawJson(pub String);

impl IntoResponse for RawJson {
    fn into_response(self) -> Response {
        ([(header::CONTENT_TYPE, "application/json")], self.0).into_response()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CipherJsonRenderOptions {
    pub force_row_query: bool,
    pub include_access_fields: bool,
}

async fn fetch_cipher_by_id(
    db: &crate::db::Db,
    cipher_id: &str,
) -> Result<CipherDBModel, AppError> {
    db.prepare("SELECT * FROM ciphers WHERE id = ?1")
        .bind(&[cipher_id.to_string().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))
}

pub(crate) fn normalize_collection_ids(collection_ids: Vec<String>) -> Vec<String> {
    collection_ids
        .into_iter()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn cipher_notification_context_from_parts(
    organization_id: Option<String>,
    collection_ids: Option<Vec<String>>,
) -> CipherNotificationContext {
    CipherNotificationContext {
        collection_ids: if organization_id.is_some() {
            Some(collection_ids.unwrap_or_default())
        } else {
            None
        },
        organization_id,
    }
}

fn cipher_notification_context_from_cipher(cipher: &Cipher) -> CipherNotificationContext {
    cipher_notification_context_from_parts(
        cipher.organization_id.clone(),
        cipher.collection_ids.clone(),
    )
}

fn cipher_notification_context_from_access(access: &CipherAccessView) -> CipherNotificationContext {
    cipher_notification_context_from_parts(
        access.organization_id.clone(),
        Some(access.collection_ids.clone()),
    )
}

fn merge_notification_collection_ids(
    old_collection_ids: Vec<String>,
    new_collection_ids: Option<Vec<String>>,
) -> Option<Vec<String>> {
    let merged = old_collection_ids
        .into_iter()
        .chain(new_collection_ids.unwrap_or_default())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    Some(merged)
}

pub(crate) async fn validate_collections_for_org(
    db: &crate::db::Db,
    org_id: &str,
    collection_ids: &[String],
) -> Result<(), AppError> {
    for collection_id in collection_ids {
        let exists: Option<String> = db
            .prepare("SELECT id FROM collections WHERE id = ?1 AND organization_id = ?2")
            .bind(&[collection_id.as_str().into(), org_id.into()])?
            .first(Some("id"))
            .await
            .map_err(|_| AppError::Database)?;

        if exists.is_none() {
            return Err(AppError::BadRequest(
                "Invalid collection for organization".to_string(),
            ));
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct OrgCipherAccessRow {
    access_all: i32,
    #[serde(rename = "type")]
    member_type: i32,
}

async fn ensure_org_cipher_write_access(
    db: &crate::db::Db,
    org_id: &str,
    user_id: &str,
    collection_ids: &[String],
) -> Result<(), AppError> {
    let membership: OrgCipherAccessRow = db
        .prepare(
            "SELECT access_all, type \
             FROM users_organizations \
             WHERE organization_id = ?1 AND user_id = ?2 AND status = ?3",
        )
        .bind(&[
            org_id.into(),
            user_id.into(),
            ORG_USER_STATUS_CONFIRMED.into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Forbidden("Organization access required".to_string()))?;

    if membership.access_all != 0 || is_org_admin_type(membership.member_type) {
        return Ok(());
    }

    if collection_ids.is_empty() {
        return Err(AppError::Forbidden(
            "Collection write access required".to_string(),
        ));
    }

    for collection_id in collection_ids {
        let read_only: Option<i32> = db
            .prepare(
                "SELECT read_only \
                 FROM users_collections \
                 WHERE user_id = ?1 AND collection_id = ?2",
            )
            .bind(&[user_id.into(), collection_id.as_str().into()])?
            .first(Some("read_only"))
            .await
            .map_err(|_| AppError::Database)?;

        match read_only {
            Some(0) => {}
            _ => {
                return Err(AppError::Forbidden(
                    "Collection write access required".to_string(),
                ));
            }
        }
    }

    Ok(())
}

pub(crate) async fn validate_cipher_org_assignment(
    db: &crate::db::Db,
    user_id: &str,
    organization_id: Option<&str>,
    collection_ids: &[String],
) -> Result<(), AppError> {
    match organization_id {
        Some(org_id) => {
            validate_collections_for_org(db, org_id, collection_ids).await?;
            ensure_org_cipher_write_access(db, org_id, user_id, collection_ids).await
        }
        None if collection_ids.is_empty() => Ok(()),
        None => Err(AppError::BadRequest(
            "Personal ciphers cannot be assigned to collections".to_string(),
        )),
    }
}

async fn ensure_org_cipher_collection_manage_access(
    db: &crate::db::Db,
    org_id: &str,
    user_id: &str,
) -> Result<(), AppError> {
    let membership: OrgCipherAccessRow = db
        .prepare(
            "SELECT access_all, type \
             FROM users_organizations \
             WHERE organization_id = ?1 AND user_id = ?2 AND status = ?3",
        )
        .bind(&[
            org_id.into(),
            user_id.into(),
            ORG_USER_STATUS_CONFIRMED.into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Forbidden("Organization access required".to_string()))?;

    if membership.access_all != 0 || is_org_admin_type(membership.member_type) {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Organization admin permissions required to change cipher collections".to_string(),
        ))
    }
}

pub(crate) async fn replace_cipher_collections(
    db: &crate::db::Db,
    cipher_id: &str,
    collection_ids: &[String],
    now: &str,
) -> Result<(), AppError> {
    let mut statements = vec![d1_query!(
        db,
        "DELETE FROM ciphers_collections WHERE cipher_id = ?1",
        cipher_id
    )
    .map_err(|_| AppError::Database)?];

    for collection_id in collection_ids {
        statements.push(
            d1_query!(
                db,
                "INSERT INTO ciphers_collections (cipher_id, collection_id, created_at) \
                 VALUES (?1, ?2, ?3)",
                cipher_id,
                collection_id,
                now
            )
            .map_err(|_| AppError::Database)?,
        );
    }

    db.batch(statements).await.map_err(|_| AppError::Database)?;
    Ok(())
}

fn reject_stale_revision(
    client_revision: Option<&str>,
    server_revision: &str,
) -> Result<(), AppError> {
    let Some(dt) = client_revision else {
        return Ok(());
    };

    match DateTime::parse_from_rfc3339(dt) {
        Ok(client_dt) => match DateTime::parse_from_rfc3339(server_revision) {
            Ok(server_dt) => {
                if server_dt.signed_duration_since(client_dt).num_seconds() > 1 {
                    return Err(AppError::BadRequest(
                        "The client copy of this cipher is out of date. Resync the client and try again.".to_string(),
                    ));
                }
            }
            Err(err) => log::warn!(
                "Error parsing server revisionDate '{}' for stale check: {}",
                server_revision,
                err
            ),
        },
        Err(err) => log::warn!("Error parsing lastKnownRevisionDate '{}': {}", dt, err),
    }

    Ok(())
}

async fn collection_ids_for_cipher(
    db: &crate::db::Db,
    cipher_id: &str,
) -> Result<Vec<String>, AppError> {
    #[derive(Deserialize)]
    struct CollectionIdRow {
        collection_id: String,
    }

    let rows: Vec<CollectionIdRow> = db
        .prepare(
            "SELECT collection_id \
             FROM ciphers_collections \
             WHERE cipher_id = ?1 \
             ORDER BY collection_id",
        )
        .bind(&[cipher_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    Ok(rows.into_iter().map(|row| row.collection_id).collect())
}

async fn hydrate_cipher_access_fields(
    db: &crate::db::Db,
    cipher: &mut Cipher,
    user_id: &str,
) -> Result<(), AppError> {
    let Some(view) = get_cipher_access_view(db, &cipher.id, user_id).await? else {
        return Ok(());
    };

    cipher.edit = view.can_edit();
    cipher.view_password = view.can_view_password();
    cipher.collection_ids = Some(view.collection_ids);
    Ok(())
}

pub(crate) async fn touch_cipher_scope_updated_at(
    db: &crate::db::Db,
    user_id: &str,
    organization_id: Option<&str>,
    now: &str,
) -> Result<(), AppError> {
    if let Some(org_id) = organization_id {
        d1_query!(
            db,
            "UPDATE users SET updated_at = ?1 \
             WHERE id IN (SELECT user_id FROM users_organizations WHERE organization_id = ?2)",
            now,
            org_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    } else {
        db::touch_user_updated_at(db, user_id, now).await?;
    }

    Ok(())
}

pub(crate) fn visible_cipher_where_clause() -> &'static str {
    "(c.organization_id IS NULL AND c.user_id = ?1)
        OR (
            c.organization_id IS NOT NULL
            AND EXISTS (
                SELECT 1
                FROM users_organizations uo
                WHERE uo.organization_id = c.organization_id
                    AND uo.user_id = ?1
                    AND uo.status = ?4
                    AND (
                        uo.access_all = 1
                        OR uo.type IN (?2, ?3)
                        OR EXISTS (
                            SELECT 1
                            FROM ciphers_collections cc
                            JOIN users_collections uc ON uc.collection_id = cc.collection_id
                            WHERE cc.cipher_id = c.id AND uc.user_id = ?1
                        )
                    )
            )
        )"
}

pub(crate) fn visible_cipher_params(user_id: &str) -> Vec<JsValue> {
    vec![
        user_id.into(),
        crate::models::organization::ORG_USER_TYPE_OWNER.into(),
        crate::models::organization::ORG_USER_TYPE_ADMIN.into(),
        crate::models::organization::ORG_USER_STATUS_CONFIRMED.into(),
    ]
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|value| !value.trim().is_empty())
    })
}

fn collection_ids_from_value(value: &Value) -> Option<Vec<String>> {
    let array = match value {
        Value::Array(values) => Some(values),
        Value::Object(map) => ["collectionIds", "CollectionIds", "collection_ids", "ids"]
            .iter()
            .find_map(|key| map.get(*key).and_then(Value::as_array)),
        _ => None,
    }?;

    Some(
        array
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
    )
}

fn ids_from_body(body: &str) -> Result<Vec<String>, AppError> {
    let value = serde_json::from_str::<Value>(body)
        .map_err(|_| AppError::BadRequest("Malformed JSON in request body".to_string()))?;
    let ids = collection_ids_from_value(&value)
        .ok_or_else(|| AppError::BadRequest("ids is required".to_string()))?;
    Ok(normalize_collection_ids(ids))
}

async fn touch_access_scopes(
    db: &crate::db::Db,
    user_id: &str,
    accesses: &[CipherAccessView],
    now: &str,
) -> Result<(), AppError> {
    let mut touch_personal = false;
    let mut org_ids = BTreeSet::new();

    for access in accesses {
        if let Some(org_id) = access.organization_id.as_ref() {
            org_ids.insert(org_id.clone());
        } else {
            touch_personal = true;
        }
    }

    if touch_personal {
        db::touch_user_updated_at(db, user_id, now).await?;
    }
    for org_id in org_ids {
        touch_cipher_scope_updated_at(db, user_id, Some(&org_id), now).await?;
    }

    Ok(())
}

fn organization_ids_from_accesses(accesses: &[CipherAccessView]) -> Vec<String> {
    accesses
        .iter()
        .filter_map(|access| access.organization_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn parse_cipher_share_payload(
    payload: Value,
) -> Result<(CipherRequestData, Vec<String>), AppError> {
    let top_collection_ids = collection_ids_from_value(&payload);
    let top_organization_id = string_field(&payload, &["organizationId", "organizationID"]);

    let mut cipher = if let Some(cipher_value) =
        payload.get("cipher").or_else(|| payload.get("Cipher"))
    {
        serde_json::from_value::<CipherRequestData>(cipher_value.clone())
            .map_err(|_| AppError::BadRequest("Invalid cipher payload for sharing".to_string()))?
    } else {
        serde_json::from_value::<CipherRequestData>(payload)
            .map_err(|_| AppError::BadRequest("Invalid cipher payload for sharing".to_string()))?
    };

    if cipher.organization_id.is_none() {
        cipher.organization_id = top_organization_id;
    }

    let collection_ids = top_collection_ids
        .or_else(|| cipher.collection_ids.clone())
        .unwrap_or_default();

    Ok((cipher, collection_ids))
}

async fn validate_folder_for_user(
    db: &crate::db::Db,
    folder_id: Option<&str>,
    user_id: &str,
) -> Result<(), AppError> {
    let Some(folder_id) = folder_id else {
        return Ok(());
    };

    let folder_exists: Option<serde_json::Value> = db
        .prepare("SELECT id FROM folders WHERE id = ?1 AND user_id = ?2")
        .bind(&[folder_id.into(), user_id.into()])?
        .first(None)
        .await?;

    if folder_exists.is_none() {
        return Err(AppError::BadRequest(
            "Invalid folder: Folder does not exist or belongs to another user".to_string(),
        ));
    }

    Ok(())
}

#[worker::send]
pub async fn create_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CreateCipherRequest>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();
    let cipher_data_req = payload.cipher;
    let collection_ids = normalize_collection_ids(payload.collection_ids);
    validate_cipher_org_assignment(
        &db,
        &claims.sub,
        cipher_data_req.organization_id.as_deref(),
        &collection_ids,
    )
    .await?;
    if cipher_data_req.organization_id.is_some() && cipher_data_req.folder_id.is_some() {
        return Err(AppError::BadRequest(
            "Organization ciphers cannot be assigned to a personal folder".to_string(),
        ));
    }
    validate_folder_for_user(&db, cipher_data_req.folder_id.as_deref(), &claims.sub).await?;

    let cipher_data = CipherData::new(
        cipher_data_req.name,
        cipher_data_req.notes,
        cipher_data_req.type_fields,
    );

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let mut cipher = Cipher {
        id: Uuid::new_v4().to_string(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        favorite: cipher_data_req.favorite.unwrap_or(false),
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: None,
        archived_at: None,
        created_at: now.clone(),
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: if collection_ids.is_empty() {
            None
        } else {
            Some(collection_ids.clone())
        },
        attachments: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    d1_query!(
        &db,
        "INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
         cipher.id,
         cipher.user_id,
         cipher.organization_id,
         cipher.r#type,
         data,
         cipher.favorite,

         cipher.folder_id,
         cipher.created_at,
         cipher.updated_at,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    replace_cipher_collections(&db, &cipher.id, &collection_ids, &now).await?;
    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    hydrate_cipher_access_fields(&db, &mut cipher, &claims.sub).await?;
    touch_cipher_scope_updated_at(
        &db,
        &claims.sub,
        cipher.organization_id.as_deref(),
        &cipher.updated_at,
    )
    .await?;

    notifications::publish_cipher_update_for_scope(
        &db,
        (*env).clone(),
        claims.sub,
        CipherUpdateNotification::new(
            UpdateType::SyncCipherCreate,
            cipher.id.clone(),
            cipher.updated_at.clone(),
            Some(claims.device),
            cipher_notification_context_from_cipher(&cipher),
        ),
    )
    .await;

    Ok(Json(cipher))
}

#[worker::send]
pub async fn update_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(_base_url)): Extension<BaseUrl>,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();

    let access = ensure_cipher_write(&db, &id, &claims.sub).await?;
    let existing_cipher = fetch_cipher_by_id(&db, &id).await?;
    let organization_id = match (
        existing_cipher.organization_id.as_ref(),
        payload.organization_id.as_ref(),
    ) {
        (Some(existing_org_id), None) => Some(existing_org_id.clone()),
        (existing_org_id, requested_org_id) if existing_org_id == requested_org_id => {
            requested_org_id.cloned()
        }
        _ => {
            return Err(AppError::BadRequest(
                "Use the cipher share route to change organization ownership".to_string(),
            ));
        }
    };
    if organization_id.is_some() && payload.folder_id.is_some() {
        return Err(AppError::BadRequest(
            "Organization ciphers cannot be assigned to a personal folder".to_string(),
        ));
    }
    let requested_collection_ids = payload.collection_ids.clone().map(normalize_collection_ids);
    if let Some(collection_ids) = requested_collection_ids.as_ref() {
        validate_cipher_org_assignment(
            &db,
            &claims.sub,
            organization_id.as_deref(),
            collection_ids,
        )
        .await?;
        if let Some(org_id) = organization_id.as_deref() {
            ensure_org_cipher_collection_manage_access(&db, org_id, &claims.sub).await?;
        }
    }

    // Validate folder ownership if provided
    if let Some(ref folder_id) = payload.folder_id {
        let folder_exists: Option<serde_json::Value> = db
            .prepare("SELECT id FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.clone().into(), claims.sub.clone().into()])?
            .first(None)
            .await?;

        if folder_exists.is_none() {
            return Err(AppError::BadRequest(
                "Invalid folder: Folder does not exist or belongs to another user".to_string(),
            ));
        }
    }

    reject_stale_revision(
        payload.last_known_revision_date.as_deref(),
        &existing_cipher.updated_at,
    )?;

    let cipher_data = CipherData::new(payload.name, payload.notes, payload.type_fields);

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let mut cipher = Cipher {
        id: id.clone(),
        user_id: Some(existing_cipher.user_id.clone()),
        organization_id,
        r#type: payload.r#type,
        data: data_value,
        favorite: payload.favorite.unwrap_or(false),
        folder_id: payload.folder_id.clone(),
        deleted_at: None,
        archived_at: existing_cipher.archived_at,
        created_at: existing_cipher.created_at,
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: Some(match requested_collection_ids.as_ref() {
            Some(collection_ids) => collection_ids.clone(),
            None => collection_ids_for_cipher(&db, &id).await?,
        }),
        attachments: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    d1_query!(
        &db,
        "UPDATE ciphers SET organization_id = ?1, type = ?2, data = ?3, favorite = ?4, folder_id = ?5, updated_at = ?6 WHERE id = ?7",
        cipher.organization_id,
        cipher.r#type,
        data,
        cipher.favorite,
        cipher.folder_id,
        cipher.updated_at,
        id,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    if let Some(collection_ids) = requested_collection_ids.as_ref() {
        replace_cipher_collections(&db, &id, collection_ids, &now).await?;
    }

    if let Some(attachments2) = &payload.attachments2 {
        for (attachment_id, attachment) in attachments2 {
            let result = d1_query!(
                &db,
                "UPDATE attachments SET file_name = ?1, akey = ?2, updated_at = ?3 WHERE id = ?4 AND cipher_id = ?5",
                attachment.file_name,
                attachment.key,
                now,
                attachment_id,
                id
            )
            .map_err(|_| AppError::Database)?
            .run()
            .await;

            if let Err(e) = result {
                log::warn!(
                    "Failed to update attachment {} for cipher {}: {:?}",
                    attachment_id,
                    id,
                    e
                );
            }
        }
    }

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    hydrate_cipher_access_fields(&db, &mut cipher, &claims.sub).await?;
    touch_cipher_scope_updated_at(
        &db,
        &claims.sub,
        cipher.organization_id.as_deref(),
        &cipher.updated_at,
    )
    .await?;

    notifications::publish_cipher_update_for_scope(
        &db,
        (*env).clone(),
        claims.sub,
        CipherUpdateNotification::new(
            UpdateType::SyncCipherUpdate,
            cipher.id.clone(),
            cipher.updated_at.clone(),
            Some(claims.device),
            cipher_notification_context_from_parts(
                cipher.organization_id.clone(),
                merge_notification_collection_ids(
                    access.collection_ids,
                    cipher.collection_ids.clone(),
                ),
            ),
        ),
    )
    .await;

    Ok(Json(cipher))
}

#[worker::send]
pub async fn share_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(payload): Json<Value>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let access = ensure_cipher_write(&db, &id, &claims.sub).await?;
    let existing_cipher = fetch_cipher_by_id(&db, &id).await?;
    let (payload, raw_collection_ids) = parse_cipher_share_payload(payload)?;
    let org_id = payload
        .organization_id
        .clone()
        .or(existing_cipher.organization_id.clone())
        .ok_or_else(|| {
            AppError::BadRequest("Organization id is required when sharing a cipher".to_string())
        })?;

    if existing_cipher
        .organization_id
        .as_ref()
        .is_some_and(|existing_org_id| existing_org_id != &org_id)
    {
        return Err(AppError::BadRequest(
            "Cross-organization cipher moves are not supported".to_string(),
        ));
    }
    if payload.folder_id.is_some() {
        return Err(AppError::BadRequest(
            "Organization ciphers cannot be assigned to a personal folder".to_string(),
        ));
    }
    reject_stale_revision(
        payload.last_known_revision_date.as_deref(),
        &existing_cipher.updated_at,
    )?;

    let collection_ids = normalize_collection_ids(raw_collection_ids);
    validate_cipher_org_assignment(&db, &claims.sub, Some(&org_id), &collection_ids).await?;
    ensure_org_cipher_collection_manage_access(&db, &org_id, &claims.sub).await?;

    let now = db::now_string();
    let cipher_data = CipherData::new(payload.name, payload.notes, payload.type_fields);
    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;
    let data = serde_json::to_string(&data_value).map_err(|_| AppError::Internal)?;

    let mut cipher = Cipher {
        id: id.clone(),
        user_id: Some(existing_cipher.user_id),
        organization_id: Some(org_id.clone()),
        r#type: payload.r#type,
        data: data_value,
        favorite: payload.favorite.unwrap_or(false),
        folder_id: None,
        deleted_at: existing_cipher.deleted_at,
        archived_at: existing_cipher.archived_at,
        created_at: existing_cipher.created_at,
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: if collection_ids.is_empty() {
            None
        } else {
            Some(collection_ids.clone())
        },
        attachments: None,
    };

    d1_query!(
        &db,
        "UPDATE ciphers SET organization_id = ?1, type = ?2, data = ?3, favorite = ?4, \
         folder_id = NULL, updated_at = ?5 WHERE id = ?6",
        org_id,
        cipher.r#type,
        data,
        cipher.favorite,
        cipher.updated_at,
        id,
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    replace_cipher_collections(&db, &cipher.id, &collection_ids, &now).await?;
    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    hydrate_cipher_access_fields(&db, &mut cipher, &claims.sub).await?;
    touch_cipher_scope_updated_at(
        &db,
        &claims.sub,
        cipher.organization_id.as_deref(),
        &cipher.updated_at,
    )
    .await?;

    notifications::publish_cipher_update_for_scope(
        &db,
        (*env).clone(),
        claims.sub,
        CipherUpdateNotification::new(
            UpdateType::SyncCipherUpdate,
            cipher.id.clone(),
            cipher.updated_at.clone(),
            Some(claims.device),
            cipher_notification_context_from_parts(
                cipher.organization_id.clone(),
                merge_notification_collection_ids(
                    access.collection_ids,
                    cipher.collection_ids.clone(),
                ),
            ),
        ),
    )
    .await;

    Ok(Json(cipher))
}

#[worker::send]
pub async fn put_cipher_collections(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(payload): Json<Value>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let access = ensure_cipher_write(&db, &id, &claims.sub).await?;
    let org_id = access.organization_id.clone().ok_or_else(|| {
        AppError::BadRequest("Personal ciphers cannot be assigned to collections".to_string())
    })?;
    let old_collection_ids = access.collection_ids.clone();
    let collection_ids = normalize_collection_ids(
        collection_ids_from_value(&payload)
            .ok_or_else(|| AppError::BadRequest("collectionIds is required".to_string()))?,
    );

    validate_cipher_org_assignment(&db, &claims.sub, Some(&org_id), &collection_ids).await?;
    ensure_org_cipher_collection_manage_access(&db, &org_id, &claims.sub).await?;

    let now = db::now_string();
    replace_cipher_collections(&db, &id, &collection_ids, &now).await?;
    d1_query!(
        &db,
        "UPDATE ciphers SET updated_at = ?1 WHERE id = ?2",
        now,
        id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let updated = fetch_cipher_by_id(&db, &id).await?;
    let mut cipher: Cipher = updated.into();
    cipher.collection_ids = Some(collection_ids);
    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    hydrate_cipher_access_fields(&db, &mut cipher, &claims.sub).await?;
    touch_cipher_scope_updated_at(&db, &claims.sub, Some(&org_id), &now).await?;

    notifications::publish_cipher_update_for_scope(
        &db,
        (*env).clone(),
        claims.sub,
        CipherUpdateNotification::new(
            UpdateType::SyncCipherUpdate,
            cipher.id.clone(),
            cipher.updated_at.clone(),
            Some(claims.device),
            cipher_notification_context_from_parts(
                Some(org_id),
                merge_notification_collection_ids(
                    old_collection_ids,
                    cipher.collection_ids.clone(),
                ),
            ),
        ),
    )
    .await;

    Ok(Json(cipher))
}

/// GET /api/ciphers - list all non-trashed ciphers for current user
#[worker::send]
pub async fn list_ciphers(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<RawJson, AppError> {
    let db = db::get_db(&env)?;
    let params = visible_cipher_params(&claims.sub);
    let where_clause = format!(
        "WHERE c.deleted_at IS NULL AND ({})",
        visible_cipher_where_clause()
    );
    build_cipher_list_response(
        &db,
        env.as_ref(),
        &where_clause,
        &params,
        "ORDER BY c.updated_at DESC",
        true,
    )
    .await
}

/// GET /api/ciphers/{id}
#[worker::send]
pub async fn get_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    ensure_cipher_read(&db, &id, &claims.sub).await?;
    let cipher = fetch_cipher_by_id(&db, &id).await?;
    let mut cipher: Cipher = cipher.into();

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    hydrate_cipher_access_fields(&db, &mut cipher, &claims.sub).await?;

    Ok(Json(cipher))
}

/// GET /api/ciphers/{id}/details
#[worker::send]
pub async fn get_cipher_details(
    claims: Claims,
    state: State<Arc<Env>>,
    id: Path<String>,
) -> Result<Json<Cipher>, AppError> {
    get_cipher(claims, state, id).await
}

/// PUT/POST /api/ciphers/{id}/partial
#[worker::send]
pub async fn update_cipher_partial(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(payload): Json<PartialCipherData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = &claims.sub;
    let access = ensure_cipher_write(&db, &id, user_id).await?;
    if access.organization_id.is_some() && payload.folder_id.is_some() {
        return Err(AppError::BadRequest(
            "Organization ciphers cannot be assigned to a personal folder".to_string(),
        ));
    }

    // Validate folder ownership if provided
    if let Some(ref folder_id) = payload.folder_id {
        let folder_exists: Option<serde_json::Value> = db
            .prepare("SELECT id FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.clone().into(), user_id.clone().into()])?
            .first(None)
            .await?;

        if folder_exists.is_none() {
            return Err(AppError::BadRequest(
                "Invalid folder: Folder does not exist or belongs to another user".to_string(),
            ));
        }
    }

    let now = db::now_string();

    d1_query!(
        &db,
        "UPDATE ciphers SET folder_id = ?1, favorite = ?2, updated_at = ?3 WHERE id = ?4",
        payload.folder_id,
        payload.favorite,
        now,
        id,
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    touch_access_scopes(&db, user_id, &[access], &now).await?;

    let cipher = fetch_cipher_by_id(&db, &id).await?;
    let mut cipher: Cipher = cipher.into();

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    hydrate_cipher_access_fields(&db, &mut cipher, user_id).await?;

    Ok(Json(cipher))
}

/// Soft delete a single cipher (PUT /api/ciphers/{id}/delete)
/// Sets deleted_at to current timestamp
#[worker::send]
pub async fn soft_delete_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let access = ensure_cipher_delete(&db, &id, &claims.sub).await?;
    let now = db::now_string();

    d1_query!(
        &db,
        "UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE id = ?2",
        now,
        id,
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let notification_context = cipher_notification_context_from_access(&access);
    touch_access_scopes(&db, &claims.sub, &[access], &now).await?;

    notifications::publish_cipher_update_for_scope(
        &db,
        (*env).clone(),
        claims.sub,
        CipherUpdateNotification::new(
            UpdateType::SyncCipherUpdate,
            id,
            now,
            Some(claims.device),
            notification_context,
        ),
    )
    .await;

    Ok(Json(()))
}

/// Soft delete multiple ciphers (PUT /api/ciphers/delete)
/// Accepts raw JSON body and uses json_each with path to extract ids directly.
/// Expected JSON: {"ids": ["cipher_id1", "cipher_id2", ...]}
#[worker::send]
pub async fn soft_delete_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();
    let ids = ids_from_body(&body)?;
    let ids_json = serde_json::to_string(&ids).map_err(|_| AppError::Internal)?;
    let mut accesses = Vec::with_capacity(ids.len());
    for id in &ids {
        accesses.push(ensure_cipher_delete(&db, id, &claims.sub).await?);
    }

    d1_query!(
        &db,
        "UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 \
         WHERE id IN (SELECT value FROM json_each(?2, '$'))",
        now,
        ids_json
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(db::map_d1_json_error)?;

    let notification_org_ids = organization_ids_from_accesses(&accesses);
    touch_access_scopes(&db, &claims.sub, &accesses, &now).await?;

    notifications::publish_user_update_for_scopes(
        &db,
        (*env).clone(),
        claims.sub.clone(),
        notification_org_ids,
        UpdateType::SyncCiphers,
        now.clone(),
        Some(claims.device),
    )
    .await;

    Ok(Json(()))
}

/// Hard delete a single cipher (DELETE /api/ciphers/{id} or POST /api/ciphers/{id}/delete)
/// Permanently removes the cipher from database
#[worker::send]
pub async fn hard_delete_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let access = ensure_cipher_delete(&db, &id, &claims.sub).await?;
    let now = db::now_string();

    if attachments::attachments_enabled(env.as_ref()) {
        let id_json = serde_json::to_string(&[&id]).map_err(|_| AppError::Internal)?;
        let keys =
            attachments::list_attachment_keys_for_cipher_ids_json(&db, &id_json, "$", None).await?;
        attachments::delete_storage_objects(env.as_ref(), &keys).await?;
    }

    d1_query!(
        &db,
        "DELETE FROM ciphers_collections WHERE cipher_id = ?1",
        id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    d1_query!(&db, "DELETE FROM ciphers WHERE id = ?1", id,)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    let notification_context = cipher_notification_context_from_access(&access);
    touch_access_scopes(&db, &claims.sub, &[access], &now).await?;

    notifications::publish_cipher_update_for_scope(
        &db,
        (*env).clone(),
        claims.sub,
        CipherUpdateNotification::new(
            UpdateType::SyncLoginDelete,
            id,
            now,
            Some(claims.device),
            notification_context,
        ),
    )
    .await;

    Ok(Json(()))
}

/// Hard delete multiple ciphers (DELETE /api/ciphers or POST /api/ciphers/delete)
/// Accepts raw JSON body and uses json_each with path to extract ids directly.
/// Expected JSON: {"ids": ["cipher_id1", "cipher_id2", ...]}
#[worker::send]
pub async fn hard_delete_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();
    let ids = ids_from_body(&body)?;
    let ids_json = serde_json::to_string(&ids).map_err(|_| AppError::Internal)?;
    let mut accesses = Vec::with_capacity(ids.len());
    for id in &ids {
        accesses.push(ensure_cipher_delete(&db, id, &claims.sub).await?);
    }

    if attachments::attachments_enabled(env.as_ref()) {
        let keys = attachments::list_attachment_keys_for_cipher_ids_json(&db, &ids_json, "$", None)
            .await?;
        attachments::delete_storage_objects(env.as_ref(), &keys).await?;
    }

    d1_query!(
        &db,
        "DELETE FROM ciphers_collections WHERE cipher_id IN (SELECT value FROM json_each(?1, '$'))",
        ids_json
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(db::map_d1_json_error)?;

    d1_query!(
        &db,
        "DELETE FROM ciphers WHERE id IN (SELECT value FROM json_each(?1, '$'))",
        ids_json
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(db::map_d1_json_error)?;

    let notification_org_ids = organization_ids_from_accesses(&accesses);
    touch_access_scopes(&db, &claims.sub, &accesses, &now).await?;

    notifications::publish_user_update_for_scopes(
        &db,
        (*env).clone(),
        claims.sub.clone(),
        notification_org_ids,
        UpdateType::SyncCiphers,
        now.clone(),
        Some(claims.device),
    )
    .await;

    Ok(Json(()))
}

/// Restore a single cipher (PUT /api/ciphers/{id}/restore)
/// Clears the deleted_at timestamp
#[worker::send]
pub async fn restore_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let access = ensure_cipher_delete(&db, &id, &claims.sub).await?;
    let now = db::now_string();

    // Update the cipher to clear deleted_at
    d1_query!(
        &db,
        "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2",
        now,
        id,
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let restored = fetch_cipher_by_id(&db, &id).await?;
    let mut cipher: Cipher = restored.into();
    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    hydrate_cipher_access_fields(&db, &mut cipher, &claims.sub).await?;

    touch_access_scopes(&db, &claims.sub, &[access], &cipher.updated_at).await?;

    notifications::publish_cipher_update_for_scope(
        &db,
        (*env).clone(),
        claims.sub,
        CipherUpdateNotification::new(
            UpdateType::SyncCipherUpdate,
            cipher.id.clone(),
            cipher.updated_at.clone(),
            Some(claims.device),
            cipher_notification_context_from_cipher(&cipher),
        ),
    )
    .await;

    Ok(Json(cipher))
}

/// Restore multiple ciphers (PUT /api/ciphers/restore)
/// Accepts raw JSON body and uses json_each with path to extract ids directly.
/// Expected JSON: {"ids": ["cipher_id1", "cipher_id2", ...]}
#[worker::send]
pub async fn restore_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<RawJson, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();
    let ids = ids_from_body(&body)?;
    let ids_json = serde_json::to_string(&ids).map_err(|_| AppError::Internal)?;
    let mut accesses = Vec::with_capacity(ids.len());
    for id in &ids {
        accesses.push(ensure_cipher_delete(&db, id, &claims.sub).await?);
    }

    // Single bulk UPDATE using json_each() with path
    d1_query!(
        &db,
        "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 \
         WHERE id IN (SELECT value FROM json_each(?2, '$'))",
        now,
        ids_json
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(db::map_d1_json_error)?;

    let notification_org_ids = organization_ids_from_accesses(&accesses);
    touch_access_scopes(&db, &claims.sub, &accesses, &now).await?;

    notifications::publish_user_update_for_scopes(
        &db,
        (*env).clone(),
        claims.sub.clone(),
        notification_org_ids,
        UpdateType::SyncCiphers,
        now.clone(),
        Some(claims.device),
    )
    .await;

    let mut params = visible_cipher_params(&claims.sub);
    params.push(ids_json.into());
    let where_clause = format!(
        "WHERE c.id IN (SELECT value FROM json_each(?5, '$')) AND ({})",
        visible_cipher_where_clause()
    );

    build_cipher_list_response(&db, env.as_ref(), &where_clause, &params, "", true).await
}

/// Archive a single cipher (PUT /api/ciphers/{id}/archive)
#[worker::send]
pub async fn archive_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let access = ensure_cipher_write(&db, &id, &claims.sub)
        .await
        .map_err(|_| {
            AppError::BadRequest(
                "Cipher was not archived. Ensure the provided ID is correct and you have permission to archive it.".to_string(),
            )
        })?;
    let now = db::now_string();

    d1_query!(
        &db,
        "UPDATE ciphers SET archived_at = ?1, updated_at = ?1 WHERE id = ?2",
        now,
        id,
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let updated = fetch_cipher_by_id(&db, &id).await?;
    let mut cipher: Cipher = updated.into();
    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    hydrate_cipher_access_fields(&db, &mut cipher, &claims.sub).await?;

    touch_access_scopes(&db, &claims.sub, &[access], &cipher.updated_at).await?;

    notifications::publish_cipher_update_for_scope(
        &db,
        (*env).clone(),
        claims.sub,
        CipherUpdateNotification::new(
            UpdateType::SyncCipherUpdate,
            cipher.id.clone(),
            cipher.updated_at.clone(),
            Some(claims.device),
            cipher_notification_context_from_cipher(&cipher),
        ),
    )
    .await;

    Ok(Json(cipher))
}

/// Unarchive a single cipher (PUT /api/ciphers/{id}/unarchive)
#[worker::send]
pub async fn unarchive_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let access = ensure_cipher_write(&db, &id, &claims.sub)
        .await
        .map_err(|_| {
            AppError::BadRequest(
                "Cipher was not unarchived. Ensure the provided ID is correct and you have permission to unarchive it.".to_string(),
            )
        })?;
    let now = db::now_string();

    d1_query!(
        &db,
        "UPDATE ciphers SET archived_at = NULL, updated_at = ?1 WHERE id = ?2",
        now,
        id,
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let updated = fetch_cipher_by_id(&db, &id).await?;
    let mut cipher: Cipher = updated.into();
    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    hydrate_cipher_access_fields(&db, &mut cipher, &claims.sub).await?;

    touch_access_scopes(&db, &claims.sub, &[access], &cipher.updated_at).await?;

    notifications::publish_cipher_update_for_scope(
        &db,
        (*env).clone(),
        claims.sub,
        CipherUpdateNotification::new(
            UpdateType::SyncCipherUpdate,
            cipher.id.clone(),
            cipher.updated_at.clone(),
            Some(claims.device),
            cipher_notification_context_from_cipher(&cipher),
        ),
    )
    .await;

    Ok(Json(cipher))
}

/// Archive multiple ciphers (PUT /api/ciphers/archive)
/// Expected JSON: {"ids": ["cipher_id1", "cipher_id2", ...]}
#[worker::send]
pub async fn archive_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<RawJson, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();
    let ids = ids_from_body(&body)?;
    let ids_json = serde_json::to_string(&ids).map_err(|_| AppError::Internal)?;
    let mut accesses = Vec::with_capacity(ids.len());
    for id in &ids {
        accesses.push(ensure_cipher_write(&db, id, &claims.sub).await?);
    }

    d1_query!(
        &db,
        "UPDATE ciphers SET archived_at = ?1, updated_at = ?1 \
         WHERE id IN (SELECT value FROM json_each(?2, '$'))",
        now,
        ids_json
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(db::map_d1_json_error)?;

    let notification_org_ids = organization_ids_from_accesses(&accesses);
    touch_access_scopes(&db, &claims.sub, &accesses, &now).await?;

    notifications::publish_user_update_for_scopes(
        &db,
        (*env).clone(),
        claims.sub.clone(),
        notification_org_ids,
        UpdateType::SyncCiphers,
        now.clone(),
        Some(claims.device),
    )
    .await;

    let mut params = visible_cipher_params(&claims.sub);
    params.push(ids_json.into());
    let where_clause = format!(
        "WHERE c.id IN (SELECT value FROM json_each(?5, '$')) AND ({})",
        visible_cipher_where_clause()
    );

    build_cipher_list_response(&db, env.as_ref(), &where_clause, &params, "", true).await
}

/// Unarchive multiple ciphers (PUT /api/ciphers/unarchive)
/// Expected JSON: {"ids": ["cipher_id1", "cipher_id2", ...]}
#[worker::send]
pub async fn unarchive_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<RawJson, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();
    let ids = ids_from_body(&body)?;
    let ids_json = serde_json::to_string(&ids).map_err(|_| AppError::Internal)?;
    let mut accesses = Vec::with_capacity(ids.len());
    for id in &ids {
        accesses.push(ensure_cipher_write(&db, id, &claims.sub).await?);
    }

    d1_query!(
        &db,
        "UPDATE ciphers SET archived_at = NULL, updated_at = ?1 \
         WHERE id IN (SELECT value FROM json_each(?2, '$'))",
        now,
        ids_json
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(db::map_d1_json_error)?;

    let notification_org_ids = organization_ids_from_accesses(&accesses);
    touch_access_scopes(&db, &claims.sub, &accesses, &now).await?;

    notifications::publish_user_update_for_scopes(
        &db,
        (*env).clone(),
        claims.sub.clone(),
        notification_org_ids,
        UpdateType::SyncCiphers,
        now.clone(),
        Some(claims.device),
    )
    .await;

    let mut params = visible_cipher_params(&claims.sub);
    params.push(ids_json.into());
    let where_clause = format!(
        "WHERE c.id IN (SELECT value FROM json_each(?5, '$')) AND ({})",
        visible_cipher_where_clause()
    );

    build_cipher_list_response(&db, env.as_ref(), &where_clause, &params, "", true).await
}

/// Handler for POST /api/ciphers
/// Accepts flat JSON structure (camelCase) as sent by Bitwarden clients
/// when creating a cipher without collection assignments.
#[worker::send]
pub async fn create_cipher_simple(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();
    let collection_ids =
        normalize_collection_ids(payload.collection_ids.clone().unwrap_or_default());
    validate_cipher_org_assignment(
        &db,
        &claims.sub,
        payload.organization_id.as_deref(),
        &collection_ids,
    )
    .await?;
    if payload.organization_id.is_some() && payload.folder_id.is_some() {
        return Err(AppError::BadRequest(
            "Organization ciphers cannot be assigned to a personal folder".to_string(),
        ));
    }
    validate_folder_for_user(&db, payload.folder_id.as_deref(), &claims.sub).await?;
    let cipher_data = CipherData::new(payload.name, payload.notes, payload.type_fields);

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let mut cipher = Cipher {
        id: Uuid::new_v4().to_string(),
        user_id: Some(claims.sub.clone()),
        organization_id: payload.organization_id.clone(),
        r#type: payload.r#type,
        data: data_value,
        favorite: payload.favorite.unwrap_or(false),
        folder_id: payload.folder_id.clone(),
        deleted_at: None,
        archived_at: None,
        created_at: now.clone(),
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: if collection_ids.is_empty() {
            None
        } else {
            Some(collection_ids.clone())
        },
        attachments: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    d1_query!(
        &db,
        "INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
         cipher.id,
         cipher.user_id,
         cipher.organization_id,
         cipher.r#type,
         data,
         cipher.favorite,
         cipher.folder_id,
         cipher.created_at,
         cipher.updated_at,
    ).map_err(|_| AppError::Database)?
    .run()
    .await?;

    replace_cipher_collections(&db, &cipher.id, &collection_ids, &now).await?;
    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    hydrate_cipher_access_fields(&db, &mut cipher, &claims.sub).await?;
    touch_cipher_scope_updated_at(
        &db,
        &claims.sub,
        cipher.organization_id.as_deref(),
        &cipher.updated_at,
    )
    .await?;

    notifications::publish_cipher_update_for_scope(
        &db,
        (*env).clone(),
        claims.sub,
        CipherUpdateNotification::new(
            UpdateType::SyncCipherCreate,
            cipher.id.clone(),
            cipher.updated_at.clone(),
            Some(claims.device),
            cipher_notification_context_from_cipher(&cipher),
        ),
    )
    .await;

    Ok(Json(cipher))
}

/// Move selected ciphers to a folder (POST/PUT /api/ciphers/move)
/// Accepts raw JSON body and uses json_extract/json_each to extract values directly.
/// Expected JSON: {"folderId": "optional-folder-id-or-null", "ids": ["cipher_id1", ...]}
/// The folderId is optional and treated as null if not provided in vaultwarden.
/// D1/SQLite's json_extract returns SQL NULL for non-existent paths, which is identical to the behavior in vaultwarden.
#[worker::send]
pub async fn move_cipher_selected(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = &claims.sub;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let body_value = serde_json::from_str::<Value>(&body)
        .map_err(|_| AppError::BadRequest("Malformed JSON in request body".to_string()))?;
    let ids = ids_from_body(&body)?;
    let ids_json = serde_json::to_string(&ids).map_err(|_| AppError::Internal)?;
    let folder_id = string_field(&body_value, &["folderId"]);

    let mut accesses = Vec::with_capacity(ids.len());
    for id in &ids {
        let access = ensure_cipher_write(&db, id, user_id).await?;
        if access.organization_id.is_some() {
            return Err(AppError::BadRequest(
                "Organization ciphers cannot be assigned to a personal folder".to_string(),
            ));
        }
        accesses.push(access);
    }

    // Validate folder exists and belongs to user (if folder_id is provided)
    if let Some(folder_id) = folder_id.as_ref() {
        validate_folder_for_user(&db, Some(folder_id), user_id).await?;
    }

    // Update folder_id for all ciphers that belong to the user and are in the ids list
    db.prepare(
        "UPDATE ciphers SET folder_id = ?1, updated_at = ?2 \
         WHERE user_id = ?3 AND id IN (SELECT value FROM json_each(?4, '$'))",
    )
    .bind(&[
        folder_id.into(),
        now.clone().into(),
        user_id.clone().into(),
        ids_json.into(),
    ])?
    .run()
    .await
    .map_err(db::map_d1_json_error)?;

    // Update user's revision date
    let notification_org_ids = organization_ids_from_accesses(&accesses);
    touch_access_scopes(&db, user_id, &accesses, &now).await?;
    notifications::publish_user_update_for_scopes(
        &db,
        (*env).clone(),
        claims.sub.clone(),
        notification_org_ids,
        UpdateType::SyncCiphers,
        now.clone(),
        Some(claims.device),
    )
    .await;

    Ok(Json(()))
}

/// Purge the user's vault - delete all ciphers and folders
/// POST /api/ciphers/purge
///
/// This is a destructive operation that requires password verification.
/// In vaultwarden, this endpoint also supports purging organization vaults,
/// but this simplified version only supports personal vault purge.
#[worker::send]
pub async fn purge_vault(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = &claims.sub;

    // Get the user from the database
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    // Validate password (OTP not supported in this simplified version)
    let provided_hash = payload
        .master_password_hash
        .ok_or_else(|| AppError::BadRequest("Missing master password hash".to_string()))?;

    let verification = user.verify_master_password(&provided_hash).await?;

    if !verification.is_valid() {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    if attachments::attachments_enabled(env.as_ref()) {
        let keys = attachments::list_attachment_keys_for_user(&db, user_id).await?;
        attachments::delete_storage_objects(env.as_ref(), &keys).await?;
    }

    // Delete all personal ciphers (both active and soft-deleted). Organization ciphers
    // stay with their organization and are managed through org collection permissions.
    d1_query!(
        &db,
        "DELETE FROM ciphers WHERE user_id = ?1 AND organization_id IS NULL",
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    // Delete all user's folders
    d1_query!(&db, "DELETE FROM folders WHERE user_id = ?1", user_id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    // Update user's revision date to trigger client sync
    let now = db::now_string();
    db::touch_user_updated_at(&db, user_id, &now).await?;

    notifications::publish_user_update(
        (*env).clone(),
        claims.sub,
        UpdateType::SyncVault,
        now,
        Some(claims.device),
    );

    Ok(Json(()))
}

#[derive(Deserialize)]
struct CipherJsonArrayRow {
    ciphers_json: String,
}

/// Build the SQL expression for a single cipher as JSON.
fn cipher_json_expr(attachments_enabled: bool, include_access_fields: bool) -> String {
    let attachments_expr = if attachments_enabled {
        "
            (
                SELECT CASE WHEN COUNT(1)=0 THEN NULL ELSE json_group_array(
                    json_object(
                        'id', a.id,
                        'url', NULL,
                        'fileName', a.file_name,
                        'size', CAST(a.file_size AS TEXT),
                        'sizeName',
                            CASE
                                WHEN a.file_size < 1024 THEN printf('%d B', a.file_size)
                                WHEN a.file_size < 1048576 THEN printf('%.1f KB', a.file_size / 1024.0)
                                WHEN a.file_size < 1073741824 THEN printf('%.1f MB', a.file_size / 1048576.0)
                                WHEN a.file_size < 1099511627776 THEN printf('%.1f GB', a.file_size / 1073741824.0)
                                ELSE printf('%.1f TB', a.file_size / 1099511627776.0)
                            END,
                        'key', a.akey,
                        'object', 'attachment'
                    )
                ) END
                FROM attachments a
                WHERE a.cipher_id = c.id
            )
        "
    } else {
        "NULL"
    };

    let (edit_expr, view_password_expr) = if include_access_fields {
        let org_admin_access = "EXISTS (
            SELECT 1
            FROM users_organizations uo_perm
            WHERE uo_perm.organization_id = c.organization_id
                AND uo_perm.user_id = ?1
                AND uo_perm.status = ?4
                AND (uo_perm.access_all = 1 OR uo_perm.type IN (?2, ?3))
        )";
        (
            format!(
                "CASE
                    WHEN c.organization_id IS NULL THEN json('true')
                    WHEN {org_admin_access} THEN json('true')
                    WHEN EXISTS (
                        SELECT 1
                        FROM ciphers_collections cc_perm
                        JOIN users_collections uc_perm ON uc_perm.collection_id = cc_perm.collection_id
                        WHERE cc_perm.cipher_id = c.id
                            AND uc_perm.user_id = ?1
                            AND uc_perm.read_only = 0
                    ) THEN json('true')
                    ELSE json('false')
                END"
            ),
            format!(
                "CASE
                    WHEN c.organization_id IS NULL THEN json('true')
                    WHEN {org_admin_access} THEN json('true')
                    WHEN EXISTS (
                        SELECT 1
                        FROM ciphers_collections cc_perm
                        JOIN users_collections uc_perm ON uc_perm.collection_id = cc_perm.collection_id
                        WHERE cc_perm.cipher_id = c.id
                            AND uc_perm.user_id = ?1
                            AND uc_perm.hide_passwords = 0
                    ) THEN json('true')
                    ELSE json('false')
                END"
            ),
        )
    } else {
        ("json('true')".to_string(), "json('true')".to_string())
    };

    format!(
        "json_object(
            'object', 'cipherDetails',
            'id', c.id,
            'userId', c.user_id,
            'organizationId', c.organization_id,
            'folderId', c.folder_id,
            'type', c.type,
            'favorite', CASE WHEN c.favorite THEN json('true') ELSE json('false') END,
            'edit', {edit_expr},
            'viewPassword', {view_password_expr},
            'permissions', json_object('delete', {edit_expr}, 'restore', {edit_expr}),
            'organizationUseTotp', json('false'),
            'collectionIds', COALESCE((
                SELECT json_group_array(cc.collection_id)
                FROM ciphers_collections cc
                WHERE cc.cipher_id = c.id
            ), json('[]')),
            'revisionDate', c.updated_at,
            'creationDate', c.created_at,
            'deletedDate', c.deleted_at,
            'archivedDate', c.archived_at,
            'attachments', {attachments_expr},
            'name', json_extract(c.data, '$.name'),
            'notes', json_extract(c.data, '$.notes'),
            'fields', COALESCE(json_extract(c.data, '$.fields'), json('[]')),
            'passwordHistory', COALESCE(json_extract(c.data, '$.passwordHistory'), json('[]')),
            'reprompt', COALESCE(json_extract(c.data, '$.reprompt'), 0),
            'login', CASE WHEN c.type = 1 THEN json_extract(c.data, '$.login') ELSE NULL END,
            'secureNote', CASE WHEN c.type = 2 THEN json_extract(c.data, '$.secureNote') ELSE NULL END,
            'card', CASE WHEN c.type = 3 THEN json_extract(c.data, '$.card') ELSE NULL END,
            'identity', CASE WHEN c.type = 4 THEN json_extract(c.data, '$.identity') ELSE NULL END,
            'sshKey', CASE WHEN c.type = 5 THEN json_extract(c.data, '$.sshKey') ELSE NULL END,
            'key', json_extract(c.data, '$.key')
        )",
        attachments_expr = attachments_expr,
        edit_expr = edit_expr,
        view_password_expr = view_password_expr,
    )
}

/// Build SQL that returns ciphers as a JSON array string (using json_group_array).
fn cipher_json_array_sql(
    attachments_enabled: bool,
    where_clause: &str,
    order_clause: &str,
    include_access_fields: bool,
) -> String {
    let cipher_expr = cipher_json_expr(attachments_enabled, include_access_fields);
    // Use a subquery to ensure ORDER BY is applied before json_group_array
    format!(
        "SELECT COALESCE(json_group_array(json(sub.cipher_json)), '[]') AS ciphers_json
        FROM (
            SELECT {cipher_expr} AS cipher_json
            FROM ciphers c
            {where_clause}
            {order_clause}
        ) sub",
        cipher_expr = cipher_expr,
        where_clause = where_clause,
        order_clause = order_clause,
    )
}

fn cipher_json_rows_sql(
    attachments_enabled: bool,
    where_clause: &str,
    order_clause: &str,
    include_access_fields: bool,
) -> String {
    let cipher_expr = cipher_json_expr(attachments_enabled, include_access_fields);
    format!(
        "SELECT {cipher_expr} AS cipher_json
        FROM ciphers c
        {where_clause}
        {order_clause}",
        cipher_expr = cipher_expr,
        where_clause = where_clause,
        order_clause = order_clause,
    )
}

fn is_sqlite_toobig(err: &worker::Error) -> bool {
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("sqlite_toobig") || msg.contains("string or blob too big")
}

/// Build a `{"data":[...],"object":"list","continuationToken":null}` response
/// using raw SQL JSON construction (no Rust-side parsing).
async fn build_cipher_list_response(
    db: &crate::db::Db,
    env: &Env,
    where_clause: &str,
    params: &[JsValue],
    order_clause: &str,
    include_access_fields: bool,
) -> Result<RawJson, AppError> {
    let include_attachments = attachments::attachments_enabled(env);
    let force_row_query = super::ciphers_default_row_query(env);
    let mut response = String::new();
    response.push_str("{\"data\":");
    append_cipher_json_array_raw(
        &mut response,
        db,
        include_attachments,
        where_clause,
        params,
        order_clause,
        CipherJsonRenderOptions {
            force_row_query,
            include_access_fields,
        },
    )
    .await?;
    response.push_str(",\"object\":\"list\",\"continuationToken\":null}");
    Ok(RawJson(response))
}

/// Append ciphers JSON array to an existing buffer.
/// This avoids JSON parsing in Rust, significantly reducing CPU time.
pub(crate) async fn append_cipher_json_array_raw(
    out: &mut String,
    db: &crate::db::Db,
    attachments_enabled: bool,
    where_clause: &str,
    params: &[JsValue],
    order_clause: &str,
    options: CipherJsonRenderOptions,
) -> Result<(), AppError> {
    if options.force_row_query {
        return append_from_rows(
            out,
            db,
            attachments_enabled,
            where_clause,
            params,
            order_clause,
            options.include_access_fields,
        )
        .await;
    }

    let sql = cipher_json_array_sql(
        attachments_enabled,
        where_clause,
        order_clause,
        options.include_access_fields,
    );

    let row: Result<Option<CipherJsonArrayRow>, worker::Error> =
        db.prepare(&sql).bind(params)?.first(None).await;

    match row {
        Ok(row) => {
            if let Some(r) = row {
                out.reserve(r.ciphers_json.len());
                out.push_str(&r.ciphers_json);
            } else {
                out.push_str("[]");
            }
            Ok(())
        }
        Err(err) if is_sqlite_toobig(&err) => {
            append_from_rows(
                out,
                db,
                attachments_enabled,
                where_clause,
                params,
                order_clause,
                options.include_access_fields,
            )
            .await
        }
        Err(err) => Err(db::map_d1_json_error(err)),
    }
}

/// Append ciphers JSON array to an existing buffer row by row.
/// This avoids JSON array exceeding the maximum size that can be returned in a single string.
///
/// Uses `raw_js_value()` to bypass Serde deserialization entirely, which should reduce
/// CPU time for large payloads. Each row from `raw_js_value()` is a JS array `[cipher_json]`
/// where the first element is the JSON string we need.
pub(crate) async fn append_from_rows(
    out: &mut String,
    db: &crate::db::Db,
    attachments_enabled: bool,
    where_clause: &str,
    params: &[JsValue],
    order_clause: &str,
    include_access_fields: bool,
) -> Result<(), AppError> {
    use js_sys::Array;
    use wasm_bindgen::JsCast;

    let sql = cipher_json_rows_sql(
        attachments_enabled,
        where_clause,
        order_clause,
        include_access_fields,
    );

    // Use raw_js_value() to get Vec<JsValue> without Serde deserialization.
    // Each JsValue is a JS array: [cipher_json_string]
    let raw_rows: Vec<JsValue> = db
        .prepare(&sql)
        .bind(params)?
        .raw_js_value()
        .await
        .map_err(db::map_d1_json_error)?;

    if raw_rows.is_empty() {
        out.push_str("[]");
        return Ok(());
    }

    out.push('[');
    for (idx, row_js) in raw_rows.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        // Each row is a JS array [column0, column1, ...]. We only select one column (cipher_json).
        let row_array = row_js
            .dyn_ref::<Array>()
            .ok_or_else(|| AppError::Internal)?;
        let cipher_json_js = row_array.get(0);
        let cipher_json = cipher_json_js
            .as_string()
            .ok_or_else(|| AppError::Internal)?;
        out.push_str(&cipher_json);
    }
    out.push(']');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_json_expression_uses_access_aliases_for_org_permissions() {
        let sql = cipher_json_expr(false, true);

        assert!(sql.contains("'collectionIds'"));
        assert!(sql.contains("json_group_array"));
        assert!(sql.contains("'edit'"));
        assert!(sql.contains("'viewPassword'"));
        assert!(sql.contains("uc_perm.read_only = 0"));
        assert!(sql.contains("uc_perm.hide_passwords = 0"));
    }

    #[test]
    fn visible_cipher_where_clause_includes_personal_and_org_access() {
        let clause = visible_cipher_where_clause();

        assert!(clause.contains("c.organization_id IS NULL"));
        assert!(clause.contains("users_organizations"));
        assert!(clause.contains("users_collections"));
        assert!(clause.contains("ciphers_collections"));
    }

    #[test]
    fn normalize_collection_ids_removes_duplicates_and_empty_values() {
        let ids = normalize_collection_ids(vec![
            "collection-2".into(),
            "".into(),
            "collection-1".into(),
            "collection-2".into(),
        ]);

        assert_eq!(
            ids,
            vec!["collection-1".to_string(), "collection-2".to_string()]
        );
    }

    #[test]
    fn organization_ids_from_accesses_dedupes_org_scope_ids() {
        let accesses = vec![
            CipherAccessView {
                cipher_id: "personal".into(),
                owner_user_id: Some("actor".into()),
                organization_id: None,
                collection_ids: Vec::new(),
                read_only: false,
                hide_passwords: false,
                manage: true,
                member_type: None,
                access_all: false,
            },
            CipherAccessView {
                cipher_id: "org-cipher-1".into(),
                owner_user_id: Some("actor".into()),
                organization_id: Some("org-b".into()),
                collection_ids: Vec::new(),
                read_only: false,
                hide_passwords: false,
                manage: true,
                member_type: Some(0),
                access_all: true,
            },
            CipherAccessView {
                cipher_id: "org-cipher-2".into(),
                owner_user_id: Some("actor".into()),
                organization_id: Some("org-a".into()),
                collection_ids: Vec::new(),
                read_only: false,
                hide_passwords: false,
                manage: true,
                member_type: Some(0),
                access_all: true,
            },
            CipherAccessView {
                cipher_id: "org-cipher-3".into(),
                owner_user_id: Some("actor".into()),
                organization_id: Some("org-b".into()),
                collection_ids: Vec::new(),
                read_only: false,
                hide_passwords: false,
                manage: true,
                member_type: Some(0),
                access_all: true,
            },
        ];

        assert_eq!(
            organization_ids_from_accesses(&accesses),
            vec!["org-a".to_string(), "org-b".to_string()]
        );
    }

    #[test]
    fn merge_notification_collection_ids_dedupes_old_and_new_ids() {
        assert_eq!(
            merge_notification_collection_ids(
                vec!["collection-b".to_string(), "collection-a".to_string()],
                Some(vec!["collection-c".to_string(), "collection-a".to_string()]),
            ),
            Some(vec![
                "collection-a".to_string(),
                "collection-b".to_string(),
                "collection-c".to_string(),
            ])
        );

        assert_eq!(
            merge_notification_collection_ids(vec!["collection-a".to_string()], None),
            Some(vec!["collection-a".to_string()])
        );
    }
}
