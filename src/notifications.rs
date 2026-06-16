#![allow(dead_code)]

use chrono::{DateTime, NaiveDateTime, Utc};
use log::warn;
use rmpv::Value;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use worker::{wasm_bindgen::JsValue, Env, Method, Request, RequestInit};

use crate::{
    db::Db,
    error::AppError,
    models::organization::{ORG_USER_STATUS_CONFIRMED, ORG_USER_TYPE_ADMIN, ORG_USER_TYPE_OWNER},
    push,
};

const INTERNAL_FANOUT_URL: &str = "https://notify.internal/fanout";
pub const RECORD_SEPARATOR: u8 = 0x1e;
pub const INITIAL_RESPONSE: [u8; 3] = [b'{', b'}', RECORD_SEPARATOR];
pub const USER_KIND_TAG: &str = "k:user";
pub const ANONYMOUS_KIND_TAG: &str = "k:anon";

// ── UpdateType ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum UpdateType {
    SyncCipherUpdate = 0,
    SyncCipherCreate = 1,
    SyncLoginDelete = 2,
    SyncFolderDelete = 3,
    SyncCiphers = 4,
    SyncVault = 5,
    SyncOrgKeys = 6,
    SyncFolderCreate = 7,
    SyncFolderUpdate = 8,
    SyncSettings = 10,
    LogOut = 11,
    SyncSendCreate = 12,
    SyncSendUpdate = 13,
    SyncSendDelete = 14,
    AuthRequest = 15,
    AuthRequestResponse = 16,
    None = 100,
}

// ── Connection model ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionKind {
    User,
    Anonymous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionAttachment {
    pub kind: ConnectionKind,
    pub user_id: Option<String>,
    pub token: Option<String>,
    pub device_id: Option<String>,
    pub protocol_initialized: bool,
    pub connected_at: String,
}

impl ConnectionAttachment {
    pub fn user(user_id: String, device_id: Option<String>, connected_at: String) -> Self {
        Self {
            kind: ConnectionKind::User,
            user_id: Some(user_id),
            token: None,
            device_id,
            protocol_initialized: false,
            connected_at,
        }
    }

    pub fn anonymous(token: String, connected_at: String) -> Self {
        Self {
            kind: ConnectionKind::Anonymous,
            user_id: None,
            token: Some(token),
            device_id: None,
            protocol_initialized: false,
            connected_at,
        }
    }

    pub fn matches_selector(&self, selector: &PublishSelector) -> bool {
        match selector {
            PublishSelector::ByUser { user_id } => {
                self.kind == ConnectionKind::User
                    && self.user_id.as_deref() == Some(user_id.as_str())
            }
            PublishSelector::ByAnonymousToken { token } => {
                self.kind == ConnectionKind::Anonymous
                    && self.token.as_deref() == Some(token.as_str())
            }
        }
    }
}

// ── Selector ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PublishSelector {
    ByUser { user_id: String },
    ByAnonymousToken { token: String },
}

impl PublishSelector {
    pub fn user(user_id: impl Into<String>) -> Self {
        Self::ByUser {
            user_id: user_id.into(),
        }
    }

    pub fn anonymous(token: impl Into<String>) -> Self {
        Self::ByAnonymousToken {
            token: token.into(),
        }
    }

    pub fn tag(&self) -> String {
        match self {
            PublishSelector::ByUser { user_id } => user_tag(user_id),
            PublishSelector::ByAnonymousToken { token } => anonymous_tag(token),
        }
    }
}

// ── Tag helpers ─────────────────────────────────────────────────────

pub fn user_tag(user_id: &str) -> String {
    format!("u:{user_id}")
}

pub fn anonymous_tag(token: &str) -> String {
    format!("a:{token}")
}

// ── Protocol helpers ────────────────────────────────────────────────

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct InitialMessage {
    protocol: String,
    version: i32,
}

pub fn is_initial_message(message: &str) -> bool {
    let message = message
        .strip_suffix(RECORD_SEPARATOR as char)
        .unwrap_or(message);

    serde_json::from_str::<InitialMessage>(message).ok()
        == Some(InitialMessage {
            protocol: "messagepack".to_string(),
            version: 1,
        })
}

// ── MessagePack helpers (used by NotifyDo) ──────────────────────────

pub fn create_ping() -> Vec<u8> {
    serialize(&Value::Array(vec![6.into()]))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CipherNotificationContext {
    pub organization_id: Option<String>,
    pub collection_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherUpdateNotification {
    pub update_type: UpdateType,
    pub cipher_id: String,
    pub revision_date: String,
    pub context_id: Option<String>,
    pub cipher_context: CipherNotificationContext,
}

impl CipherUpdateNotification {
    pub fn new(
        update_type: UpdateType,
        cipher_id: String,
        revision_date: String,
        context_id: Option<String>,
        cipher_context: CipherNotificationContext,
    ) -> Self {
        Self {
            update_type,
            cipher_id,
            revision_date,
            context_id,
            cipher_context,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CipherNotificationTarget {
    user_id: String,
    context_id: Option<String>,
}

fn cipher_notification_targets(
    actor_user_id: &str,
    recipient_user_ids: Vec<String>,
    actor_context_id: Option<String>,
) -> Vec<CipherNotificationTarget> {
    let mut targets = Vec::new();
    targets.push(CipherNotificationTarget {
        user_id: actor_user_id.to_string(),
        context_id: actor_context_id,
    });

    for recipient_user_id in recipient_user_ids {
        if targets
            .iter()
            .any(|target| target.user_id == recipient_user_id)
        {
            continue;
        }
        targets.push(CipherNotificationTarget {
            user_id: recipient_user_id,
            context_id: None,
        });
    }

    targets
}

async fn cipher_notification_recipient_user_ids(
    db: &Db,
    actor_user_id: &str,
    cipher_id: &str,
    context: &CipherNotificationContext,
) -> Result<Vec<String>, AppError> {
    let Some(org_id) = context.organization_id.as_deref() else {
        return Ok(vec![actor_user_id.to_string()]);
    };

    let rows = if let Some(collection_ids) = context.collection_ids.as_ref() {
        let collection_ids_json =
            serde_json::to_string(collection_ids).map_err(|_| AppError::Internal)?;
        db.prepare(
            "SELECT DISTINCT uo.user_id \
             FROM users_organizations uo \
             WHERE uo.organization_id = ?1 \
                AND uo.status = ?4 \
                AND ( \
                    uo.access_all = 1 \
                    OR uo.type IN (?2, ?3) \
                    OR EXISTS ( \
                        SELECT 1 \
                        FROM users_collections uc \
                        WHERE uc.user_id = uo.user_id \
                            AND uc.collection_id IN (SELECT value FROM json_each(?5, '$')) \
                    ) \
                )",
        )
        .bind(&[
            org_id.into(),
            ORG_USER_TYPE_OWNER.into(),
            ORG_USER_TYPE_ADMIN.into(),
            ORG_USER_STATUS_CONFIRMED.into(),
            collection_ids_json.into(),
        ])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results::<JsonValue>()
        .unwrap_or_default()
    } else {
        db.prepare(
            "SELECT DISTINCT uo.user_id \
             FROM users_organizations uo \
             WHERE uo.organization_id = ?1 \
                AND uo.status = ?4 \
                AND ( \
                    uo.access_all = 1 \
                    OR uo.type IN (?2, ?3) \
                    OR EXISTS ( \
                        SELECT 1 \
                        FROM ciphers_collections cc \
                        JOIN users_collections uc \
                            ON uc.collection_id = cc.collection_id \
                            AND uc.user_id = uo.user_id \
                        WHERE cc.cipher_id = ?5 \
                    ) \
                )",
        )
        .bind(&[
            org_id.into(),
            ORG_USER_TYPE_OWNER.into(),
            ORG_USER_TYPE_ADMIN.into(),
            ORG_USER_STATUS_CONFIRMED.into(),
            cipher_id.into(),
        ])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results::<JsonValue>()
        .unwrap_or_default()
    };

    let recipient_user_ids = rows
        .into_iter()
        .filter_map(|row| {
            row.get("user_id")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .collect();

    Ok(recipient_user_ids)
}

fn cipher_collection_ids_value(collection_ids: Option<&[String]>) -> Value {
    collection_ids
        .map(|ids| Value::Array(ids.iter().map(|id| id.as_str().into()).collect()))
        .unwrap_or(Value::Nil)
}

fn cipher_update_payload(
    user_id: &str,
    cipher_id: &str,
    revision_date: &str,
    context: &CipherNotificationContext,
) -> Vec<(Value, Value)> {
    vec![
        ("Id".into(), cipher_id.into()),
        ("UserId".into(), user_id.into()),
        (
            "OrganizationId".into(),
            convert_option(context.organization_id.as_deref()),
        ),
        (
            "CollectionIds".into(),
            cipher_collection_ids_value(context.collection_ids.as_deref()),
        ),
        (
            "RevisionDate".into(),
            serialize_date(parse_timestamp(revision_date)),
        ),
    ]
}

// ── DO fan-out protocol ─────────────────────────────────────────────

#[derive(Serialize)]
struct DoFanoutRequest<'a> {
    selector: &'a PublishSelector,
    message: String,
}

async fn send_ws_to_do(env: &Env, selector: &PublishSelector, ws_bytes: &[u8]) {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let selector_tag = selector.tag();
    let namespace = match env.durable_object("NOTIFY_DO") {
        Ok(namespace) => namespace,
        Err(error) => {
            warn!("Skipping ws notification for {selector_tag}: NOTIFY_DO lookup failed: {error}");
            return;
        }
    };
    let stub = match namespace.get_by_name("global") {
        Ok(stub) => stub,
        Err(error) => {
            warn!("Skipping ws notification for {selector_tag}: DO stub lookup failed: {error}");
            return;
        }
    };

    let body = match serde_json::to_string(&DoFanoutRequest {
        selector,
        message: STANDARD.encode(ws_bytes),
    }) {
        Ok(body) => body,
        Err(error) => {
            warn!("Skipping ws notification for {selector_tag}: payload encode failed: {error}");
            return;
        }
    };

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(JsValue::from_str(&body)));

    let mut request = match Request::new_with_init(INTERNAL_FANOUT_URL, &init) {
        Ok(request) => request,
        Err(error) => {
            warn!("Skipping ws notification for {selector_tag}: request creation failed: {error}");
            return;
        }
    };
    let headers = match request.headers_mut() {
        Ok(headers) => headers,
        Err(error) => {
            warn!("Skipping ws notification for {selector_tag}: headers init failed: {error}");
            return;
        }
    };
    if let Err(error) = headers.set("Content-Type", "application/json") {
        warn!("Skipping ws notification for {selector_tag}: header set failed: {error}");
        return;
    }

    let mut response = match stub.fetch_with_request(request).await {
        Ok(response) => response,
        Err(error) => {
            warn!("Skipping ws notification for {selector_tag}: DO fanout failed: {error}");
            return;
        }
    };
    if !(200..300).contains(&response.status_code()) {
        let status = response.status_code();
        let body = response.text().await.unwrap_or_else(|_| String::new());
        warn!("Skipping ws notification for {selector_tag}: NotifyDo fanout failed with status {status}: {body}");
    }
}

// ── Publish helpers (called by handlers) ────────────────────────────

pub fn publish_user_update(
    env: Env,
    user_id: String,
    update_type: UpdateType,
    date: String,
    context_id: Option<String>,
) {
    crate::background::spawn_background(async move {
        let ws_bytes = create_update(
            vec![
                ("UserId".into(), user_id.as_str().into()),
                ("Date".into(), serialize_date(parse_timestamp(&date))),
            ],
            update_type as i32,
            context_id.as_deref(),
        );
        let selector = PublishSelector::user(&user_id);
        futures_util::join!(
            send_ws_to_do(&env, &selector, &ws_bytes),
            push::push_user_update(
                &env,
                &user_id,
                update_type as i32,
                &date,
                context_id.as_deref()
            ),
        );
    });
}

pub fn publish_user_logout(env: Env, user_id: String, date: String, context_id: Option<String>) {
    publish_user_update(env, user_id, UpdateType::LogOut, date, context_id)
}

async fn org_scope_notification_recipient_user_ids(
    db: &Db,
    actor_user_id: &str,
    organization_ids: &[String],
) -> Result<Vec<String>, AppError> {
    if organization_ids.is_empty() {
        return Ok(vec![actor_user_id.to_string()]);
    }

    let organization_ids_json =
        serde_json::to_string(organization_ids).map_err(|_| AppError::Internal)?;
    let rows = db
        .prepare(
            "SELECT DISTINCT user_id \
             FROM users_organizations \
             WHERE status = ?1 \
                AND organization_id IN (SELECT value FROM json_each(?2, '$'))",
        )
        .bind(&[
            ORG_USER_STATUS_CONFIRMED.into(),
            organization_ids_json.into(),
        ])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results::<JsonValue>()
        .unwrap_or_default();

    Ok(rows
        .into_iter()
        .filter_map(|row| {
            row.get("user_id")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .collect())
}

pub async fn publish_user_update_for_scopes(
    db: &Db,
    env: Env,
    actor_user_id: String,
    organization_ids: Vec<String>,
    update_type: UpdateType,
    date: String,
    context_id: Option<String>,
) {
    let recipient_user_ids = match org_scope_notification_recipient_user_ids(
        db,
        &actor_user_id,
        &organization_ids,
    )
    .await
    {
        Ok(recipient_user_ids) => recipient_user_ids,
        Err(error) => {
            warn!("Failed to resolve scoped notification recipients: {error}");
            vec![actor_user_id.clone()]
        }
    };

    for target in cipher_notification_targets(&actor_user_id, recipient_user_ids, context_id) {
        publish_user_update(
            env.clone(),
            target.user_id,
            update_type,
            date.clone(),
            target.context_id,
        );
    }
}

pub fn publish_folder_update(
    env: Env,
    user_id: String,
    update_type: UpdateType,
    folder_id: String,
    revision_date: String,
    context_id: Option<String>,
) {
    crate::background::spawn_background(async move {
        let ws_bytes = create_update(
            vec![
                ("Id".into(), folder_id.as_str().into()),
                ("UserId".into(), user_id.as_str().into()),
                (
                    "RevisionDate".into(),
                    serialize_date(parse_timestamp(&revision_date)),
                ),
            ],
            update_type as i32,
            context_id.as_deref(),
        );
        let selector = PublishSelector::user(&user_id);
        futures_util::join!(
            send_ws_to_do(&env, &selector, &ws_bytes),
            push::push_folder_update(
                &env,
                &user_id,
                update_type as i32,
                &folder_id,
                &revision_date,
                context_id.as_deref(),
            ),
        );
    });
}

pub fn publish_cipher_update(
    env: Env,
    user_id: String,
    update_type: UpdateType,
    cipher_id: String,
    revision_date: String,
    context_id: Option<String>,
) {
    publish_cipher_update_with_context(
        env,
        user_id,
        update_type,
        cipher_id,
        revision_date,
        context_id,
        CipherNotificationContext::default(),
    );
}

pub async fn publish_cipher_update_for_scope(
    db: &Db,
    env: Env,
    actor_user_id: String,
    notification: CipherUpdateNotification,
) {
    let recipient_user_ids = match cipher_notification_recipient_user_ids(
        db,
        &actor_user_id,
        &notification.cipher_id,
        &notification.cipher_context,
    )
    .await
    {
        Ok(recipient_user_ids) => recipient_user_ids,
        Err(error) => {
            let cipher_id = &notification.cipher_id;
            warn!("Failed to resolve notification recipients for cipher {cipher_id}: {error}");
            vec![actor_user_id.clone()]
        }
    };

    publish_cipher_update_to_users(env, actor_user_id, recipient_user_ids, notification);
}

pub fn publish_cipher_update_to_users(
    env: Env,
    actor_user_id: String,
    recipient_user_ids: Vec<String>,
    notification: CipherUpdateNotification,
) {
    for target in cipher_notification_targets(
        &actor_user_id,
        recipient_user_ids,
        notification.context_id.clone(),
    ) {
        publish_cipher_update_with_context(
            env.clone(),
            target.user_id,
            notification.update_type,
            notification.cipher_id.clone(),
            notification.revision_date.clone(),
            target.context_id,
            notification.cipher_context.clone(),
        );
    }
}

pub fn publish_cipher_update_with_context(
    env: Env,
    user_id: String,
    update_type: UpdateType,
    cipher_id: String,
    revision_date: String,
    context_id: Option<String>,
    cipher_context: CipherNotificationContext,
) {
    crate::background::spawn_background(async move {
        let ws_bytes = create_update(
            cipher_update_payload(&user_id, &cipher_id, &revision_date, &cipher_context),
            update_type as i32,
            context_id.as_deref(),
        );
        let push_context = push::CipherPushContext {
            organization_id: cipher_context.organization_id,
            collection_ids: cipher_context.collection_ids,
        };
        let selector = PublishSelector::user(&user_id);
        futures_util::join!(
            send_ws_to_do(&env, &selector, &ws_bytes),
            push::push_cipher_update_with_context(
                &env,
                &user_id,
                update_type as i32,
                &cipher_id,
                &revision_date,
                context_id.as_deref(),
                push_context,
            ),
        );
    });
}

pub fn publish_send_update(
    env: Env,
    user_id: String,
    update_type: UpdateType,
    send_id: String,
    revision_date: String,
    context_id: Option<String>,
) {
    crate::background::spawn_background(async move {
        let ws_bytes = create_update(
            vec![
                ("Id".into(), send_id.as_str().into()),
                ("UserId".into(), user_id.as_str().into()),
                (
                    "RevisionDate".into(),
                    serialize_date(parse_timestamp(&revision_date)),
                ),
            ],
            update_type as i32,
            context_id.as_deref(),
        );
        let selector = PublishSelector::user(&user_id);
        futures_util::join!(
            send_ws_to_do(&env, &selector, &ws_bytes),
            push::push_send_update(
                &env,
                &user_id,
                update_type as i32,
                &send_id,
                &revision_date,
                context_id.as_deref(),
            ),
        );
    });
}

pub fn publish_auth_update(
    env: Env,
    user_id: String,
    update_type: UpdateType,
    auth_request_id: String,
    context_id: Option<String>,
) {
    crate::background::spawn_background(async move {
        let ws_bytes = create_update(
            vec![
                ("Id".into(), auth_request_id.as_str().into()),
                ("UserId".into(), user_id.as_str().into()),
            ],
            update_type as i32,
            context_id.as_deref(),
        );
        let selector = PublishSelector::user(&user_id);
        futures_util::join!(
            send_ws_to_do(&env, &selector, &ws_bytes),
            push::push_auth_update(
                &env,
                &user_id,
                update_type as i32,
                &auth_request_id,
                context_id.as_deref(),
            ),
        );
    });
}

pub fn publish_anonymous_update(env: Env, token: String, user_id: String, auth_request_id: String) {
    crate::background::spawn_background(async move {
        let ws_bytes = create_anonymous_update(
            vec![
                ("Id".into(), auth_request_id.as_str().into()),
                ("UserId".into(), user_id.as_str().into()),
            ],
            UpdateType::AuthRequestResponse as i32,
            &user_id,
        );
        let selector = PublishSelector::anonymous(&token);
        send_ws_to_do(&env, &selector, &ws_bytes).await;
    });
}

// ── MessagePack internals ───────────────────────────────────────────

fn create_update(
    payload: Vec<(Value, Value)>,
    update_type: i32,
    context_id: Option<&str>,
) -> Vec<u8> {
    use rmpv::Value as V;

    let value = V::Array(vec![
        1.into(),
        V::Map(vec![]),
        V::Nil,
        "ReceiveMessage".into(),
        V::Array(vec![V::Map(vec![
            ("ContextId".into(), convert_option(context_id)),
            ("Type".into(), update_type.into()),
            ("Payload".into(), payload.into()),
        ])]),
    ]);

    serialize(&value)
}

fn create_anonymous_update(
    payload: Vec<(Value, Value)>,
    update_type: i32,
    user_id: &str,
) -> Vec<u8> {
    use rmpv::Value as V;

    let value = V::Array(vec![
        1.into(),
        V::Map(vec![]),
        V::Nil,
        "AuthRequestResponseRecieved".into(),
        V::Array(vec![V::Map(vec![
            ("Type".into(), update_type.into()),
            ("Payload".into(), payload.into()),
            ("UserId".into(), user_id.into()),
        ])]),
    ]);

    serialize(&value)
}

fn serialize(value: &Value) -> Vec<u8> {
    use rmpv::encode::write_value;

    let mut buffer = Vec::new();
    write_value(&mut buffer, value).expect("msgpack encoding should not fail");

    let mut size = buffer.len();
    let mut prefix = Vec::new();

    loop {
        let mut size_part = size & 0x7f;
        size >>= 7;

        if size > 0 {
            size_part |= 0x80;
        }

        prefix.push(size_part as u8);

        if size == 0 {
            break;
        }
    }

    prefix.append(&mut buffer);
    prefix
}

fn serialize_date(date: NaiveDateTime) -> Value {
    let seconds = date.and_utc().timestamp();
    let nanos = i64::from(date.and_utc().timestamp_subsec_nanos());
    let timestamp = (nanos << 34) | seconds;

    Value::Ext(-1, timestamp.to_be_bytes().to_vec())
}

fn convert_option<T: Into<Value>>(option: Option<T>) -> Value {
    match option {
        Some(value) => value.into(),
        None => Value::Nil,
    }
}

fn parse_timestamp(date: &str) -> NaiveDateTime {
    if date.is_empty() {
        return Utc::now().naive_utc();
    }

    DateTime::parse_from_rfc3339(date)
        .map(|value| value.naive_utc())
        .unwrap_or_else(|error| {
            warn!("Failed to parse RFC3339 timestamp '{date}': {error}");
            Utc::now().naive_utc()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_payload_value<'a>(payload: &'a [(Value, Value)], key: &str) -> &'a Value {
        payload
            .iter()
            .find_map(|(payload_key, payload_value)| {
                (payload_key.as_str() == Some(key)).then_some(payload_value)
            })
            .expect("payload key should exist")
    }

    #[test]
    fn cipher_update_payload_includes_org_and_collection_context() {
        let context = CipherNotificationContext {
            organization_id: Some("org-1".to_string()),
            collection_ids: Some(vec!["collection-1".to_string(), "collection-2".to_string()]),
        };

        let payload = cipher_update_payload("user-1", "cipher-1", "2026-06-15T12:00:00Z", &context);

        assert_eq!(
            find_payload_value(&payload, "OrganizationId"),
            &Value::from("org-1")
        );
        assert_eq!(
            find_payload_value(&payload, "CollectionIds"),
            &Value::Array(vec![
                Value::from("collection-1"),
                Value::from("collection-2"),
            ])
        );
    }

    #[test]
    fn cipher_notification_targets_dedupe_and_keep_actor_context_only_for_actor() {
        let targets = cipher_notification_targets(
            "actor-user",
            vec![
                "other-user".to_string(),
                "actor-user".to_string(),
                "other-user".to_string(),
                "third-user".to_string(),
            ],
            Some("actor-device".to_string()),
        );

        assert_eq!(
            targets,
            vec![
                CipherNotificationTarget {
                    user_id: "actor-user".to_string(),
                    context_id: Some("actor-device".to_string()),
                },
                CipherNotificationTarget {
                    user_id: "other-user".to_string(),
                    context_id: None,
                },
                CipherNotificationTarget {
                    user_id: "third-user".to_string(),
                    context_id: None,
                },
            ]
        );
    }
}
