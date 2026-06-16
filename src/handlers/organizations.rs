use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use uuid::Uuid;
use worker::Env;

use crate::{
    auth::Claims,
    d1_query, db,
    db::Db,
    error::AppError,
    models::{
        collection::{CollectionDetails, CollectionRequest, CollectionUserRequest},
        organization::{
            is_org_admin_type, CreateOrganizationRequest, OrganizationKeysRequest,
            ProfileOrganization, ORG_USER_STATUS_ACCEPTED, ORG_USER_STATUS_CONFIRMED,
            ORG_USER_STATUS_INVITED, ORG_USER_TYPE_ADMIN, ORG_USER_TYPE_MANAGER,
            ORG_USER_TYPE_OWNER, ORG_USER_TYPE_USER,
        },
        user::User,
    },
};

#[derive(Debug, Deserialize)]
pub(crate) struct ProfileOrganizationRow {
    pub id: String,
    pub organization_user_id: String,
    pub user_id: String,
    pub name: String,
    pub key: Option<String>,
    pub status: i32,
    #[serde(rename = "type")]
    pub member_type: i32,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
}

pub(crate) fn profile_rows_to_json(rows: Vec<ProfileOrganizationRow>) -> Vec<Value> {
    rows.into_iter()
        .map(|row| {
            ProfileOrganization {
                id: row.id,
                organization_user_id: row.organization_user_id,
                user_id: row.user_id,
                name: row.name,
                key: row.key.unwrap_or_default(),
                status: row.status,
                r#type: row.member_type,
                has_public_and_private_keys: row.private_key.is_some() && row.public_key.is_some(),
            }
            .to_json()
        })
        .collect()
}

pub(crate) async fn profile_organizations_for_user(
    db: &Db,
    user_id: &str,
) -> Result<Vec<Value>, AppError> {
    let rows: Vec<ProfileOrganizationRow> = db
        .prepare(
            "SELECT o.id, uo.id AS organization_user_id, uo.user_id, o.name, uo.key, \
                    uo.status, uo.type, o.private_key, o.public_key \
             FROM users_organizations uo \
             JOIN organizations o ON o.id = uo.organization_id \
             WHERE uo.user_id = ?1 AND uo.status IN (?2, ?3) \
             ORDER BY o.name COLLATE NOCASE",
        )
        .bind(&[
            user_id.into(),
            ORG_USER_STATUS_ACCEPTED.into(),
            ORG_USER_STATUS_CONFIRMED.into(),
        ])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    Ok(profile_rows_to_json(rows))
}

#[derive(Debug, Deserialize)]
pub(crate) struct CollectionDetailsRow {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub external_id: Option<String>,
    pub read_only: i32,
    pub hide_passwords: i32,
    pub manage: i32,
}

impl From<CollectionDetailsRow> for CollectionDetails {
    fn from(row: CollectionDetailsRow) -> Self {
        Self {
            id: row.id,
            organization_id: row.organization_id,
            name: row.name,
            external_id: row.external_id,
            read_only: row.read_only != 0,
            hide_passwords: row.hide_passwords != 0,
            manage: row.manage != 0,
        }
    }
}

pub(crate) fn collection_details_to_json_array(rows: Vec<CollectionDetails>) -> String {
    let values: Vec<Value> = rows
        .into_iter()
        .map(|collection| collection.to_json())
        .collect();
    serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string())
}

pub(crate) async fn visible_collections_for_user_json(
    db: &Db,
    user_id: &str,
) -> Result<String, AppError> {
    let rows: Vec<CollectionDetailsRow> = db
        .prepare(
            "SELECT \
                c.id, \
                c.organization_id, \
                c.name, \
                c.external_id, \
                CASE WHEN uo.access_all = 1 OR uo.type IN (?2, ?3) THEN 0 ELSE COALESCE(uc.read_only, 0) END AS read_only, \
                CASE WHEN uo.access_all = 1 OR uo.type IN (?2, ?3) THEN 0 ELSE COALESCE(uc.hide_passwords, 0) END AS hide_passwords, \
                CASE WHEN uo.access_all = 1 OR uo.type IN (?2, ?3) THEN 1 ELSE COALESCE(uc.manage, 0) END AS manage \
             FROM collections c \
             JOIN users_organizations uo ON uo.organization_id = c.organization_id \
             LEFT JOIN users_collections uc ON uc.collection_id = c.id AND uc.user_id = ?1 \
             WHERE uo.user_id = ?1 \
                AND uo.status = ?4 \
                AND (uo.access_all = 1 OR uo.type IN (?2, ?3) OR uc.user_id IS NOT NULL) \
             ORDER BY c.name COLLATE NOCASE",
        )
        .bind(&[
            user_id.into(),
            ORG_USER_TYPE_OWNER.into(),
            ORG_USER_TYPE_ADMIN.into(),
            ORG_USER_STATUS_CONFIRMED.into(),
        ])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    let collections = rows.into_iter().map(CollectionDetails::from).collect();
    Ok(collection_details_to_json_array(collections))
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct OrganizationMembershipRow {
    pub id: String,
    pub user_id: String,
    pub organization_id: String,
    pub access_all: i32,
    pub key: Option<String>,
    pub status: i32,
    #[serde(rename = "type")]
    pub member_type: i32,
}

#[allow(dead_code)]
impl OrganizationMembershipRow {
    pub fn is_confirmed(&self) -> bool {
        self.status == ORG_USER_STATUS_CONFIRMED
    }

    pub fn is_admin(&self) -> bool {
        self.is_confirmed() && is_org_admin_type(self.member_type)
    }
}

fn is_valid_org_member_type(member_type: i32) -> bool {
    matches!(
        member_type,
        ORG_USER_TYPE_OWNER | ORG_USER_TYPE_ADMIN | ORG_USER_TYPE_USER | ORG_USER_TYPE_MANAGER
    )
}

fn resolve_requested_member_type(
    requested_member_type: Option<i32>,
    default_member_type: i32,
    caller_member_type: i32,
) -> Result<i32, AppError> {
    let member_type = requested_member_type.unwrap_or(default_member_type);
    if !is_valid_org_member_type(member_type) {
        return Err(AppError::BadRequest(
            "Invalid organization user type".to_string(),
        ));
    }
    if member_type == ORG_USER_TYPE_OWNER && caller_member_type != ORG_USER_TYPE_OWNER {
        return Err(AppError::Forbidden(
            "Organization owner permissions required".to_string(),
        ));
    }

    Ok(member_type)
}

fn ensure_owner_retained_after_member_change(
    current_status: i32,
    current_member_type: i32,
    next_member_type: Option<i32>,
    confirmed_owner_count: u32,
) -> Result<(), AppError> {
    let removes_confirmed_owner = current_status == ORG_USER_STATUS_CONFIRMED
        && current_member_type == ORG_USER_TYPE_OWNER
        && next_member_type != Some(ORG_USER_TYPE_OWNER);

    if removes_confirmed_owner && confirmed_owner_count <= 1 {
        return Err(AppError::Conflict(
            "Organization must keep at least one confirmed owner".to_string(),
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
struct OrganizationRow {
    id: String,
    name: String,
    billing_email: Option<String>,
    private_key: Option<String>,
    public_key: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone)]
struct OrganizationDetailsView {
    id: String,
    name: String,
    billing_email: Option<String>,
    private_key: Option<String>,
    public_key: Option<String>,
    created_at: String,
    updated_at: String,
    member_id: Option<String>,
    member_type: Option<i32>,
}

impl OrganizationDetailsView {
    fn from_row(row: OrganizationRow, member: Option<&OrganizationMembershipRow>) -> Self {
        Self {
            id: row.id,
            name: row.name,
            billing_email: row.billing_email,
            private_key: row.private_key,
            public_key: row.public_key,
            created_at: row.created_at,
            updated_at: row.updated_at,
            member_id: member.map(|membership| membership.id.clone()),
            member_type: member.map(|membership| membership.member_type),
        }
    }
}

fn list_response(data: Vec<Value>) -> Value {
    json!({
        "data": data,
        "object": "list",
        "continuationToken": null
    })
}

fn org_compatibility_empty_list() -> Value {
    list_response(Vec::new())
}

fn org_subscription_stub(org_id: &str) -> Value {
    json!({
        "object": "organizationSubscription",
        "organizationId": org_id,
        "enabled": false,
        "status": "unsupported",
        "plan": null
    })
}

fn organization_permissions_json(member_type: Option<i32>) -> Value {
    let can_manage_collections = member_type.map(is_org_admin_type).unwrap_or(false);
    json!({
        "accessEventLogs": can_manage_collections,
        "accessImportExport": can_manage_collections,
        "accessReports": can_manage_collections,
        "createNewCollections": can_manage_collections,
        "editAnyCollection": can_manage_collections,
        "deleteAnyCollection": can_manage_collections,
        "manageUsers": can_manage_collections,
        "manageGroups": false,
        "manageSso": false,
        "managePolicies": can_manage_collections,
        "manageResetPassword": false
    })
}

fn organization_details_json(details: &OrganizationDetailsView) -> Value {
    let can_manage_collections = details.member_type.map(is_org_admin_type).unwrap_or(false);
    json!({
        "object": "organization",
        "id": details.id,
        "name": details.name,
        "billingEmail": details.billing_email,
        "enabled": true,
        "planType": 0,
        "seats": null,
        "maxCollections": null,
        "maxStorageGb": null,
        "use2fa": false,
        "useDirectory": false,
        "useEvents": false,
        "useGroups": false,
        "usePolicies": true,
        "useSso": false,
        "useTotp": true,
        "usersGetPremium": true,
        "selfHost": true,
        "hasPublicAndPrivateKeys": details.private_key.is_some() && details.public_key.is_some(),
        "privateKey": details.private_key,
        "publicKey": details.public_key,
        "organizationUserId": details.member_id,
        "permissions": organization_permissions_json(details.member_type),
        "allowAdminAccessToAllCollectionItems": can_manage_collections,
        "canAccessEventLogs": can_manage_collections,
        "canAccessImportExport": can_manage_collections,
        "canAccessReports": can_manage_collections,
        "canCreateNewCollections": can_manage_collections,
        "canDeleteAnyCollection": can_manage_collections,
        "canEditAllCiphers": can_manage_collections,
        "canEditAnyCollection": can_manage_collections,
        "canEditUnassignedCiphers": can_manage_collections,
        "canEditUnmanagedCollections": can_manage_collections,
        "canManagePolicies": can_manage_collections,
        "canManageUsers": can_manage_collections,
        "limitCollectionCreation": !can_manage_collections,
        "limitCollectionDeletion": !can_manage_collections,
        "creationDate": details.created_at,
        "revisionDate": details.updated_at
    })
}

fn organization_keys_json(private_key: Option<String>, public_key: Option<String>) -> Value {
    let encrypted_private_key = private_key.clone();
    json!({
        "object": "organizationKeys",
        "privateKey": private_key,
        "encryptedPrivateKey": encrypted_private_key,
        "publicKey": public_key
    })
}

#[derive(Debug, Clone)]
struct OrganizationUserView {
    id: String,
    user_id: String,
    organization_id: String,
    name: Option<String>,
    email: String,
    access_all: bool,
    key: Option<String>,
    status: i32,
    member_type: i32,
    external_id: Option<String>,
    collections: Vec<Value>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct OrganizationUserRow {
    id: String,
    user_id: String,
    organization_id: String,
    name: Option<String>,
    email: String,
    access_all: i32,
    key: Option<String>,
    status: i32,
    #[serde(rename = "type")]
    member_type: i32,
    external_id: Option<String>,
    created_at: String,
    updated_at: String,
}

impl From<OrganizationUserRow> for OrganizationUserView {
    fn from(row: OrganizationUserRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            organization_id: row.organization_id,
            name: row.name,
            email: row.email,
            access_all: row.access_all != 0,
            key: row.key,
            status: row.status,
            member_type: row.member_type,
            external_id: row.external_id,
            collections: Vec::new(),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

fn organization_user_json(member: &OrganizationUserView) -> Value {
    json!({
        "object": "organizationUser",
        "id": member.id,
        "userId": member.user_id,
        "organizationId": member.organization_id,
        "name": member.name,
        "email": member.email,
        "accessAll": member.access_all,
        "key": member.key,
        "status": member.status,
        "type": member.member_type,
        "externalId": member.external_id,
        "resetPasswordKey": null,
        "resetPasswordEnrolled": false,
        "collections": member.collections,
        "groups": [],
        "creationDate": member.created_at,
        "revisionDate": member.updated_at
    })
}

async fn touch_org_members_updated_at(db: &Db, org_id: &str, now: &str) -> Result<(), AppError> {
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

    Ok(())
}

async fn fetch_organization_row(db: &Db, org_id: &str) -> Result<OrganizationRow, AppError> {
    db.prepare(
        "SELECT id, name, billing_email, private_key, public_key, created_at, updated_at \
         FROM organizations \
         WHERE id = ?1",
    )
    .bind(&[org_id.into()])?
    .first(None)
    .await
    .map_err(|_| AppError::Database)?
    .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))
}

async fn fetch_membership(
    db: &Db,
    org_id: &str,
    user_id: &str,
) -> Result<Option<OrganizationMembershipRow>, AppError> {
    db.prepare(
        "SELECT id, user_id, organization_id, access_all, key, status, type \
         FROM users_organizations \
         WHERE organization_id = ?1 AND user_id = ?2",
    )
    .bind(&[org_id.into(), user_id.into()])?
    .first(None)
    .await
    .map_err(|_| AppError::Database)
}

async fn fetch_membership_by_id(
    db: &Db,
    org_id: &str,
    member_id: &str,
) -> Result<Option<OrganizationMembershipRow>, AppError> {
    db.prepare(
        "SELECT id, user_id, organization_id, access_all, key, status, type \
         FROM users_organizations \
         WHERE organization_id = ?1 AND id = ?2",
    )
    .bind(&[org_id.into(), member_id.into()])?
    .first(None)
    .await
    .map_err(|_| AppError::Database)
}

async fn confirmed_owner_count(db: &Db, org_id: &str) -> Result<u32, AppError> {
    let count: Option<f64> = db
        .prepare(
            "SELECT COUNT(1) AS count \
             FROM users_organizations \
             WHERE organization_id = ?1 AND status = ?2 AND type = ?3",
        )
        .bind(&[
            org_id.into(),
            ORG_USER_STATUS_CONFIRMED.into(),
            ORG_USER_TYPE_OWNER.into(),
        ])?
        .first(Some("count"))
        .await
        .map_err(|_| AppError::Database)?;

    Ok(count.unwrap_or(0.0) as u32)
}

async fn ensure_org_member(
    db: &Db,
    org_id: &str,
    user_id: &str,
) -> Result<OrganizationMembershipRow, AppError> {
    let membership = fetch_membership(db, org_id, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if matches!(
        membership.status,
        ORG_USER_STATUS_ACCEPTED | ORG_USER_STATUS_CONFIRMED
    ) {
        Ok(membership)
    } else {
        Err(AppError::NotFound("Organization not found".to_string()))
    }
}

async fn ensure_org_admin(
    db: &Db,
    org_id: &str,
    user_id: &str,
) -> Result<OrganizationMembershipRow, AppError> {
    let membership = fetch_membership(db, org_id, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if membership.is_admin() {
        Ok(membership)
    } else {
        Err(AppError::Forbidden(
            "Organization admin permissions required".to_string(),
        ))
    }
}

async fn organization_details_for_member(
    db: &Db,
    org_id: &str,
    membership: &OrganizationMembershipRow,
) -> Result<Value, AppError> {
    let row = fetch_organization_row(db, org_id).await?;
    Ok(organization_details_json(
        &OrganizationDetailsView::from_row(row, Some(membership)),
    ))
}

async fn collection_belongs_to_org(
    db: &Db,
    org_id: &str,
    collection_id: &str,
) -> Result<(), AppError> {
    let exists: Option<String> = db
        .prepare("SELECT id FROM collections WHERE id = ?1 AND organization_id = ?2")
        .bind(&[collection_id.into(), org_id.into()])?
        .first(Some("id"))
        .await
        .map_err(|_| AppError::Database)?;

    exists
        .map(|_| ())
        .ok_or_else(|| AppError::NotFound("Collection not found".to_string()))
}

async fn collection_rows_for_membership(
    db: &Db,
    org_id: &str,
    membership: &OrganizationMembershipRow,
) -> Result<Vec<CollectionDetails>, AppError> {
    let rows: Vec<CollectionDetailsRow> =
        if membership.access_all != 0 || is_org_admin_type(membership.member_type) {
            db.prepare(
                "SELECT id, organization_id, name, external_id, \
                    0 AS read_only, 0 AS hide_passwords, 1 AS manage \
                 FROM collections \
                 WHERE organization_id = ?1 \
                 ORDER BY name COLLATE NOCASE",
            )
            .bind(&[org_id.into()])?
            .all()
            .await
            .map_err(|_| AppError::Database)?
            .results()
            .map_err(|_| AppError::Database)?
        } else {
            db.prepare(
                "SELECT c.id, c.organization_id, c.name, c.external_id, \
                    uc.read_only, uc.hide_passwords, uc.manage \
                 FROM collections c \
                 JOIN users_collections uc ON uc.collection_id = c.id \
                 WHERE c.organization_id = ?1 AND uc.user_id = ?2 \
                 ORDER BY c.name COLLATE NOCASE",
            )
            .bind(&[org_id.into(), membership.user_id.as_str().into()])?
            .all()
            .await
            .map_err(|_| AppError::Database)?
            .results()
            .map_err(|_| AppError::Database)?
        };

    Ok(rows.into_iter().map(CollectionDetails::from).collect())
}

async fn organization_user_view_by_id(
    db: &Db,
    org_id: &str,
    member_id: &str,
) -> Result<OrganizationUserView, AppError> {
    let mut view = db
        .prepare(
            "SELECT uo.id, uo.user_id, uo.organization_id, u.name, u.email, \
            uo.access_all, uo.key, uo.status, uo.type, uo.external_id, \
            uo.created_at, uo.updated_at \
         FROM users_organizations uo \
         JOIN users u ON u.id = uo.user_id \
         WHERE uo.organization_id = ?1 AND uo.id = ?2",
        )
        .bind(&[org_id.into(), member_id.into()])?
        .first::<OrganizationUserRow>(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(OrganizationUserView::from)
        .ok_or_else(|| AppError::NotFound("Organization user not found".to_string()))?;

    view.collections = member_collection_values(db, org_id, &view.user_id).await?;
    Ok(view)
}

async fn organization_user_views(
    db: &Db,
    org_id: &str,
) -> Result<Vec<OrganizationUserView>, AppError> {
    let rows: Vec<OrganizationUserRow> = db
        .prepare(
            "SELECT uo.id, uo.user_id, uo.organization_id, u.name, u.email, \
                uo.access_all, uo.key, uo.status, uo.type, uo.external_id, \
                uo.created_at, uo.updated_at \
             FROM users_organizations uo \
             JOIN users u ON u.id = uo.user_id \
             WHERE uo.organization_id = ?1 \
             ORDER BY u.email COLLATE NOCASE",
        )
        .bind(&[org_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    let mut views = Vec::with_capacity(rows.len());
    for row in rows {
        let mut view = OrganizationUserView::from(row);
        view.collections = member_collection_values(db, org_id, &view.user_id).await?;
        views.push(view);
    }

    Ok(views)
}

#[derive(Debug, Deserialize)]
struct MemberCollectionRow {
    id: String,
    read_only: i32,
    hide_passwords: i32,
    manage: i32,
}

async fn member_collection_values(
    db: &Db,
    org_id: &str,
    user_id: &str,
) -> Result<Vec<Value>, AppError> {
    let rows: Vec<MemberCollectionRow> = db
        .prepare(
            "SELECT c.id, uc.read_only, uc.hide_passwords, uc.manage \
             FROM users_collections uc \
             JOIN collections c ON c.id = uc.collection_id \
             WHERE c.organization_id = ?1 AND uc.user_id = ?2 \
             ORDER BY c.name COLLATE NOCASE",
        )
        .bind(&[org_id.into(), user_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    Ok(rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.id,
                "readOnly": row.read_only != 0,
                "hidePasswords": row.hide_passwords != 0,
                "manage": row.manage != 0
            })
        })
        .collect())
}

async fn replace_collection_users(
    db: &Db,
    org_id: &str,
    collection_id: &str,
    users: &[CollectionUserRequest],
    now: &str,
) -> Result<(), AppError> {
    let mut resolved_users: BTreeMap<String, (bool, bool, bool)> = BTreeMap::new();
    for user in users {
        let membership: OrganizationMembershipRow = db
            .prepare(
                "SELECT id, user_id, organization_id, access_all, key, status, type \
                 FROM users_organizations \
                 WHERE organization_id = ?1 AND (id = ?2 OR user_id = ?2)",
            )
            .bind(&[org_id.into(), user.id.as_str().into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?
            .ok_or_else(|| AppError::BadRequest("Invalid organization user".to_string()))?;

        resolved_users.insert(
            membership.user_id,
            (user.read_only, user.hide_passwords, user.manage),
        );
    }

    let mut statements = vec![d1_query!(
        db,
        "DELETE FROM users_collections WHERE collection_id = ?1",
        collection_id
    )
    .map_err(|_| AppError::Database)?];

    for (user_id, (read_only, hide_passwords, manage)) in resolved_users {
        statements.push(
            d1_query!(
            db,
            "INSERT INTO users_collections \
                (user_id, collection_id, read_only, hide_passwords, manage, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            user_id,
            collection_id,
            i32::from(read_only),
            i32::from(hide_passwords),
            i32::from(manage),
            now,
            now
        )
            .map_err(|_| AppError::Database)?,
        );
    }

    db.batch(statements).await.map_err(|_| AppError::Database)?;

    Ok(())
}

async fn validate_member_collections(
    db: &Db,
    org_id: &str,
    collections: &[MemberCollectionRequest],
) -> Result<(), AppError> {
    for collection in collections {
        collection_belongs_to_org(db, org_id, &collection.id).await?;
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OrganizationUpdateRequest {
    name: Option<String>,
    billing_email: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InviteOrgUsersRequest {
    #[serde(default)]
    emails: Vec<String>,
    email: Option<String>,
    #[serde(rename = "type")]
    member_type: Option<i32>,
    access_all: Option<bool>,
}

impl InviteOrgUsersRequest {
    fn normalized_emails(&self) -> Vec<String> {
        let mut emails = BTreeSet::new();
        for email in &self.emails {
            let email = email.trim().to_ascii_lowercase();
            if !email.is_empty() {
                emails.insert(email);
            }
        }
        if let Some(email) = &self.email {
            let email = email.trim().to_ascii_lowercase();
            if !email.is_empty() {
                emails.insert(email);
            }
        }
        emails.into_iter().collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfirmOrgUserRequest {
    key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationUserKeyRequest {
    id: String,
    key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfirmOrgUsersRequest {
    #[serde(default)]
    keys: Vec<OrganizationUserKeyRequest>,
    #[serde(default)]
    users: Vec<OrganizationUserKeyRequest>,
}

impl ConfirmOrgUsersRequest {
    fn entries(self) -> Vec<OrganizationUserKeyRequest> {
        if self.keys.is_empty() {
            self.users
        } else {
            self.keys
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberCollectionRequest {
    id: String,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    hide_passwords: bool,
    #[serde(default)]
    manage: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OrganizationUserUpdateRequest {
    #[serde(rename = "type")]
    member_type: Option<i32>,
    access_all: Option<bool>,
    key: Option<String>,
    collections: Option<Vec<MemberCollectionRequest>>,
    #[serde(default)]
    groups: Vec<Value>,
}

async fn replace_member_collections(
    db: &Db,
    org_id: &str,
    user_id: &str,
    collections: &[MemberCollectionRequest],
    now: &str,
) -> Result<(), AppError> {
    let mut deduped: BTreeMap<String, (bool, bool, bool)> = BTreeMap::new();
    for collection in collections {
        collection_belongs_to_org(db, org_id, &collection.id).await?;
        deduped.insert(
            collection.id.clone(),
            (
                collection.read_only,
                collection.hide_passwords,
                collection.manage,
            ),
        );
    }

    let mut statements = vec![d1_query!(
        db,
        "DELETE FROM users_collections \
         WHERE user_id = ?1 \
            AND collection_id IN (SELECT id FROM collections WHERE organization_id = ?2)",
        user_id,
        org_id
    )
    .map_err(|_| AppError::Database)?];

    for (collection_id, (read_only, hide_passwords, manage)) in deduped {
        statements.push(
            d1_query!(
            db,
            "INSERT INTO users_collections \
                (user_id, collection_id, read_only, hide_passwords, manage, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            user_id,
            collection_id,
            i32::from(read_only),
            i32::from(hide_passwords),
            i32::from(manage),
            now,
            now
        )
            .map_err(|_| AppError::Database)?,
        );
    }

    db.batch(statements).await.map_err(|_| AppError::Database)?;

    Ok(())
}

fn ids_from_public_keys_payload(payload: &Value) -> Vec<String> {
    let arrays = match payload {
        Value::Array(values) => vec![values],
        Value::Object(map) => ["ids", "organizationUserIds", "users"]
            .iter()
            .filter_map(|key| map.get(*key).and_then(Value::as_array))
            .collect(),
        _ => Vec::new(),
    };

    let mut ids = BTreeSet::new();
    for values in arrays {
        for value in values {
            match value {
                Value::String(id) if !id.is_empty() => {
                    ids.insert(id.clone());
                }
                Value::Object(map) => {
                    if let Some(Value::String(id)) = map.get("id") {
                        if !id.is_empty() {
                            ids.insert(id.clone());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    ids.into_iter().collect()
}

#[worker::send]
pub async fn create_organization(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CreateOrganizationRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();
    let org_id = Uuid::new_v4().to_string();
    let member_id = Uuid::new_v4().to_string();
    let collection_id = Uuid::new_v4().to_string();
    let private_key = payload
        .keys
        .as_ref()
        .map(|keys| keys.encrypted_private_key.clone());
    let public_key = payload.keys.as_ref().map(|keys| keys.public_key.clone());

    d1_query!(
        &db,
        "INSERT INTO organizations \
            (id, name, billing_email, private_key, public_key, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        org_id,
        payload.name,
        payload.billing_email,
        private_key,
        public_key,
        now,
        now
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    d1_query!(
        &db,
        "INSERT INTO users_organizations \
            (id, user_id, organization_id, invited_by_email, access_all, key, status, type, \
             reset_password_key, external_id, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, NULL, NULL, ?8, ?9)",
        member_id,
        claims.sub,
        org_id,
        claims.email,
        payload.key,
        ORG_USER_STATUS_CONFIRMED,
        ORG_USER_TYPE_OWNER,
        now,
        now
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    d1_query!(
        &db,
        "INSERT INTO collections (id, organization_id, name, external_id, created_at, updated_at) \
         VALUES (?1, ?2, ?3, NULL, ?4, ?5)",
        collection_id,
        org_id,
        payload.collection_name,
        now,
        now
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    d1_query!(
        &db,
        "INSERT INTO users_collections \
            (user_id, collection_id, read_only, hide_passwords, manage, created_at, updated_at) \
         VALUES (?1, ?2, 0, 0, 1, ?3, ?4)",
        claims.sub,
        collection_id,
        now,
        now
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    touch_org_members_updated_at(&db, &org_id, &now).await?;

    let member = OrganizationMembershipRow {
        id: member_id,
        user_id: claims.sub,
        organization_id: org_id.clone(),
        access_all: 1,
        key: Some(payload.key),
        status: ORG_USER_STATUS_CONFIRMED,
        member_type: ORG_USER_TYPE_OWNER,
    };
    let org = fetch_organization_row(&db, &org_id).await?;

    Ok(Json(organization_details_json(
        &OrganizationDetailsView::from_row(org, Some(&member)),
    )))
}

#[worker::send]
pub async fn get_organization(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let membership = ensure_org_member(&db, &org_id, &claims.sub).await?;
    Ok(Json(
        organization_details_for_member(&db, &org_id, &membership).await?,
    ))
}

#[worker::send]
pub async fn update_organization(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(payload): Json<OrganizationUpdateRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let membership = ensure_org_admin(&db, &org_id, &claims.sub).await?;
    let existing = fetch_organization_row(&db, &org_id).await?;
    let now = db::now_string();
    let name = payload.name.unwrap_or(existing.name);
    let billing_email = payload.billing_email.or(existing.billing_email);

    d1_query!(
        &db,
        "UPDATE organizations SET name = ?1, billing_email = ?2, updated_at = ?3 WHERE id = ?4",
        name,
        billing_email,
        now,
        org_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    touch_org_members_updated_at(&db, &org_id, &now).await?;

    Ok(Json(
        organization_details_for_member(&db, &org_id, &membership).await?,
    ))
}

#[worker::send]
pub async fn post_organization_keys(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(payload): Json<OrganizationKeysRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_admin(&db, &org_id, &claims.sub).await?;
    let now = db::now_string();

    d1_query!(
        &db,
        "UPDATE organizations SET private_key = ?1, public_key = ?2, updated_at = ?3 WHERE id = ?4",
        payload.encrypted_private_key,
        payload.public_key,
        now,
        org_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    touch_org_members_updated_at(&db, &org_id, &now).await?;

    Ok(Json(organization_keys_json(
        Some(payload.encrypted_private_key),
        Some(payload.public_key),
    )))
}

#[worker::send]
pub async fn get_organization_keys(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_member(&db, &org_id, &claims.sub).await?;
    let org = fetch_organization_row(&db, &org_id).await?;

    Ok(Json(organization_keys_json(
        org.private_key,
        org.public_key,
    )))
}

#[worker::send]
pub async fn get_organization_public_key(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_member(&db, &org_id, &claims.sub).await?;
    let org = fetch_organization_row(&db, &org_id).await?;

    Ok(Json(json!({
        "object": "organizationPublicKey",
        "publicKey": org.public_key
    })))
}

#[worker::send]
pub async fn list_org_collections(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let membership = ensure_org_member(&db, &org_id, &claims.sub).await?;
    let collections = collection_rows_for_membership(&db, &org_id, &membership).await?;
    let values = collections
        .into_iter()
        .map(|collection| collection.to_json())
        .collect();

    Ok(Json(list_response(values)))
}

#[worker::send]
pub async fn list_org_collections_details(
    claims: Claims,
    state: State<Arc<Env>>,
    org_id: Path<String>,
) -> Result<Json<Value>, AppError> {
    list_org_collections(claims, state, org_id).await
}

#[worker::send]
pub async fn list_all_collections(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let collections_json = visible_collections_for_user_json(&db, &claims.sub).await?;
    let data = serde_json::from_str::<Vec<Value>>(&collections_json).unwrap_or_default();
    Ok(Json(list_response(data)))
}

#[worker::send]
pub async fn create_collection(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(payload): Json<CollectionRequest>,
) -> Result<Json<Value>, AppError> {
    if !payload.groups.is_empty() {
        return Err(AppError::BadRequest("Groups are not supported".to_string()));
    }

    let db = db::get_db(&env)?;
    ensure_org_admin(&db, &org_id, &claims.sub).await?;
    let now = db::now_string();
    let collection_id = Uuid::new_v4().to_string();

    d1_query!(
        &db,
        "INSERT INTO collections (id, organization_id, name, external_id, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        collection_id,
        org_id,
        payload.name,
        payload.external_id,
        now,
        now
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    replace_collection_users(&db, &org_id, &collection_id, &payload.users, &now).await?;
    touch_org_members_updated_at(&db, &org_id, &now).await?;

    Ok(Json(
        CollectionDetails {
            id: collection_id,
            organization_id: org_id,
            name: payload.name,
            external_id: payload.external_id,
            read_only: false,
            hide_passwords: false,
            manage: true,
        }
        .to_json(),
    ))
}

#[worker::send]
pub async fn update_collection(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, collection_id)): Path<(String, String)>,
    Json(payload): Json<CollectionRequest>,
) -> Result<Json<Value>, AppError> {
    if !payload.groups.is_empty() {
        return Err(AppError::BadRequest("Groups are not supported".to_string()));
    }

    let db = db::get_db(&env)?;
    ensure_org_admin(&db, &org_id, &claims.sub).await?;
    collection_belongs_to_org(&db, &org_id, &collection_id).await?;
    let now = db::now_string();

    d1_query!(
        &db,
        "UPDATE collections SET name = ?1, external_id = ?2, updated_at = ?3 \
         WHERE id = ?4 AND organization_id = ?5",
        payload.name,
        payload.external_id,
        now,
        collection_id,
        org_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    replace_collection_users(&db, &org_id, &collection_id, &payload.users, &now).await?;
    touch_org_members_updated_at(&db, &org_id, &now).await?;

    Ok(Json(
        CollectionDetails {
            id: collection_id,
            organization_id: org_id,
            name: payload.name,
            external_id: payload.external_id,
            read_only: false,
            hide_passwords: false,
            manage: true,
        }
        .to_json(),
    ))
}

#[worker::send]
pub async fn delete_collection(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, collection_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_admin(&db, &org_id, &claims.sub).await?;
    collection_belongs_to_org(&db, &org_id, &collection_id).await?;
    let now = db::now_string();

    d1_query!(
        &db,
        "DELETE FROM ciphers_collections WHERE collection_id = ?1",
        collection_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    d1_query!(
        &db,
        "DELETE FROM users_collections WHERE collection_id = ?1",
        collection_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    d1_query!(
        &db,
        "DELETE FROM collections WHERE id = ?1 AND organization_id = ?2",
        collection_id,
        org_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    touch_org_members_updated_at(&db, &org_id, &now).await?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn list_org_users(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_admin(&db, &org_id, &claims.sub).await?;
    let values = organization_user_views(&db, &org_id)
        .await?
        .into_iter()
        .map(|member| organization_user_json(&member))
        .collect();

    Ok(Json(list_response(values)))
}

#[worker::send]
pub async fn invite_org_users(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(payload): Json<InviteOrgUsersRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let caller = ensure_org_admin(&db, &org_id, &claims.sub).await?;
    let emails = payload.normalized_emails();
    if emails.is_empty() {
        return Err(AppError::BadRequest(
            "At least one email is required".to_string(),
        ));
    }
    let invited_member_type =
        resolve_requested_member_type(payload.member_type, ORG_USER_TYPE_USER, caller.member_type)?;

    let mut users = Vec::with_capacity(emails.len());
    for email in emails {
        let user = User::find_by_email(&db, &email)
            .await?
            .ok_or_else(|| AppError::BadRequest("User must register before invite".to_string()))?;
        users.push(user);
    }

    let now = db::now_string();
    let mut values = Vec::with_capacity(users.len());
    for user in users {
        let existing = fetch_membership(&db, &org_id, &user.id).await?;
        if existing.is_some() {
            return Err(AppError::Conflict(
                "User is already in the organization".to_string(),
            ));
        }

        let member_id = Uuid::new_v4().to_string();
        d1_query!(
            &db,
            "INSERT INTO users_organizations \
                (id, user_id, organization_id, invited_by_email, access_all, key, status, type, \
                 reset_password_key, external_id, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, NULL, NULL, ?8, ?9)",
            member_id,
            user.id,
            org_id,
            claims.email,
            i32::from(payload.access_all.unwrap_or(false)),
            ORG_USER_STATUS_INVITED,
            invited_member_type,
            now,
            now
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

        values.push(organization_user_json(
            &organization_user_view_by_id(&db, &org_id, &member_id).await?,
        ));
    }

    touch_org_members_updated_at(&db, &org_id, &now).await?;

    Ok(Json(list_response(values)))
}

#[worker::send]
pub async fn accept_org_user(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let membership = fetch_membership_by_id(&db, &org_id, &member_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization user not found".to_string()))?;

    if membership.user_id != claims.sub {
        return Err(AppError::NotFound(
            "Organization user not found".to_string(),
        ));
    }

    let now = db::now_string();
    if membership.status == ORG_USER_STATUS_INVITED {
        d1_query!(
            &db,
            "UPDATE users_organizations SET status = ?1, updated_at = ?2 \
             WHERE id = ?3 AND organization_id = ?4",
            ORG_USER_STATUS_ACCEPTED,
            now,
            member_id,
            org_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        touch_org_members_updated_at(&db, &org_id, &now).await?;
    }

    Ok(Json(organization_user_json(
        &organization_user_view_by_id(&db, &org_id, &member_id).await?,
    )))
}

#[worker::send]
pub async fn confirm_org_user(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(payload): Json<ConfirmOrgUserRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let caller = ensure_org_admin(&db, &org_id, &claims.sub).await?;
    let target = fetch_membership_by_id(&db, &org_id, &member_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization user not found".to_string()))?;
    if target.member_type == ORG_USER_TYPE_OWNER && caller.member_type != ORG_USER_TYPE_OWNER {
        return Err(AppError::Forbidden(
            "Organization owner permissions required".to_string(),
        ));
    }
    if target.status == ORG_USER_STATUS_CONFIRMED {
        return Err(AppError::Conflict(
            "Organization user is already confirmed".to_string(),
        ));
    }
    let now = db::now_string();

    d1_query!(
        &db,
        "UPDATE users_organizations SET key = ?1, status = ?2, updated_at = ?3 \
         WHERE id = ?4 AND organization_id = ?5",
        payload.key,
        ORG_USER_STATUS_CONFIRMED,
        now,
        member_id,
        org_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    touch_org_members_updated_at(&db, &org_id, &now).await?;

    Ok(Json(organization_user_json(
        &organization_user_view_by_id(&db, &org_id, &member_id).await?,
    )))
}

#[worker::send]
pub async fn confirm_org_users(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(payload): Json<ConfirmOrgUsersRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let caller = ensure_org_admin(&db, &org_id, &claims.sub).await?;
    let entries = payload.entries();
    if entries.is_empty() {
        return Err(AppError::BadRequest(
            "At least one organization user key is required".to_string(),
        ));
    }

    for entry in &entries {
        let target = fetch_membership_by_id(&db, &org_id, &entry.id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization user not found".to_string()))?;
        if target.member_type == ORG_USER_TYPE_OWNER && caller.member_type != ORG_USER_TYPE_OWNER {
            return Err(AppError::Forbidden(
                "Organization owner permissions required".to_string(),
            ));
        }
        if target.status == ORG_USER_STATUS_CONFIRMED {
            return Err(AppError::Conflict(
                "Organization user is already confirmed".to_string(),
            ));
        }
    }

    let now = db::now_string();
    let mut values = Vec::with_capacity(entries.len());
    for entry in entries {
        d1_query!(
            &db,
            "UPDATE users_organizations SET key = ?1, status = ?2, updated_at = ?3 \
             WHERE id = ?4 AND organization_id = ?5",
            entry.key,
            ORG_USER_STATUS_CONFIRMED,
            now,
            entry.id,
            org_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

        values.push(organization_user_json(
            &organization_user_view_by_id(&db, &org_id, &entry.id).await?,
        ));
    }

    touch_org_members_updated_at(&db, &org_id, &now).await?;

    Ok(Json(list_response(values)))
}

#[worker::send]
pub async fn get_org_user(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let caller = fetch_membership(&db, &org_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let target = fetch_membership_by_id(&db, &org_id, &member_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization user not found".to_string()))?;

    if !caller.is_admin() && target.user_id != claims.sub {
        return Err(AppError::Forbidden(
            "Organization admin permissions required".to_string(),
        ));
    }

    Ok(Json(organization_user_json(
        &organization_user_view_by_id(&db, &org_id, &member_id).await?,
    )))
}

#[worker::send]
pub async fn update_org_user(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(payload): Json<OrganizationUserUpdateRequest>,
) -> Result<Json<Value>, AppError> {
    if !payload.groups.is_empty() {
        return Err(AppError::BadRequest("Groups are not supported".to_string()));
    }

    let db = db::get_db(&env)?;
    let caller = ensure_org_admin(&db, &org_id, &claims.sub).await?;
    let existing = fetch_membership_by_id(&db, &org_id, &member_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization user not found".to_string()))?;
    if existing.member_type == ORG_USER_TYPE_OWNER && caller.member_type != ORG_USER_TYPE_OWNER {
        return Err(AppError::Forbidden(
            "Organization owner permissions required".to_string(),
        ));
    }
    let member_type = resolve_requested_member_type(
        payload.member_type,
        existing.member_type,
        caller.member_type,
    )?;
    let owner_count = if existing.status == ORG_USER_STATUS_CONFIRMED
        && existing.member_type == ORG_USER_TYPE_OWNER
        && member_type != ORG_USER_TYPE_OWNER
    {
        confirmed_owner_count(&db, &org_id).await?
    } else {
        0
    };
    ensure_owner_retained_after_member_change(
        existing.status,
        existing.member_type,
        Some(member_type),
        owner_count,
    )?;
    if let Some(collections) = payload.collections.as_ref() {
        validate_member_collections(&db, &org_id, collections).await?;
    }
    let now = db::now_string();
    let access_all = payload
        .access_all
        .map(i32::from)
        .unwrap_or(existing.access_all);
    let key = payload.key.or(existing.key);

    d1_query!(
        &db,
        "UPDATE users_organizations SET access_all = ?1, key = ?2, type = ?3, updated_at = ?4 \
         WHERE id = ?5 AND organization_id = ?6",
        access_all,
        key,
        member_type,
        now,
        member_id,
        org_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    if let Some(collections) = payload.collections {
        replace_member_collections(&db, &org_id, &existing.user_id, &collections, &now).await?;
    }

    touch_org_members_updated_at(&db, &org_id, &now).await?;

    Ok(Json(organization_user_json(
        &organization_user_view_by_id(&db, &org_id, &member_id).await?,
    )))
}

#[worker::send]
pub async fn delete_org_user(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let caller = ensure_org_admin(&db, &org_id, &claims.sub).await?;
    let target = fetch_membership_by_id(&db, &org_id, &member_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization user not found".to_string()))?;
    if target.member_type == ORG_USER_TYPE_OWNER && caller.member_type != ORG_USER_TYPE_OWNER {
        return Err(AppError::Forbidden(
            "Organization owner permissions required".to_string(),
        ));
    }
    let owner_count = if target.status == ORG_USER_STATUS_CONFIRMED
        && target.member_type == ORG_USER_TYPE_OWNER
    {
        confirmed_owner_count(&db, &org_id).await?
    } else {
        0
    };
    ensure_owner_retained_after_member_change(
        target.status,
        target.member_type,
        None,
        owner_count,
    )?;
    let now = db::now_string();

    d1_query!(
        &db,
        "DELETE FROM users_collections \
         WHERE user_id = ?1 \
            AND collection_id IN (SELECT id FROM collections WHERE organization_id = ?2)",
        target.user_id,
        org_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    d1_query!(
        &db,
        "DELETE FROM users_organizations WHERE id = ?1 AND organization_id = ?2",
        member_id,
        org_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    touch_org_members_updated_at(&db, &org_id, &now).await?;
    db::touch_user_updated_at(&db, &target.user_id, &now).await?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_org_users_public_keys(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_admin(&db, &org_id, &claims.sub).await?;
    let requested_ids = ids_from_public_keys_payload(&payload);
    let members = if requested_ids.is_empty() {
        organization_user_views(&db, &org_id).await?
    } else {
        let mut members = Vec::with_capacity(requested_ids.len());
        for member_id in requested_ids {
            members.push(organization_user_view_by_id(&db, &org_id, &member_id).await?);
        }
        members
    };

    let mut values = Vec::with_capacity(members.len());
    for member in members {
        let public_key: Option<String> = db
            .prepare("SELECT public_key FROM users WHERE id = ?1")
            .bind(&[member.user_id.as_str().into()])?
            .first(Some("public_key"))
            .await
            .map_err(|_| AppError::Database)?;

        values.push(json!({
            "object": "organizationUserPublicKey",
            "id": member.id,
            "userId": member.user_id,
            "publicKey": public_key
        }));
    }

    Ok(Json(list_response(values)))
}

#[worker::send]
pub async fn list_org_policies(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_member(&db, &org_id, &claims.sub).await?;
    Ok(Json(list_response(Vec::new())))
}

#[worker::send]
pub async fn get_org_policy(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, policy_type)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_member(&db, &org_id, &claims.sub).await?;
    Ok(Json(json!({
        "object": "policy",
        "organizationId": org_id,
        "type": policy_type,
        "enabled": false,
        "data": null
    })))
}

#[worker::send]
pub async fn list_org_groups(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_member(&db, &org_id, &claims.sub).await?;
    Ok(Json(list_response(Vec::new())))
}

#[worker::send]
pub async fn post_org_groups(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_admin(&db, &org_id, &claims.sub).await?;
    let is_empty = match &payload {
        Value::Null => true,
        Value::Array(values) => values.is_empty(),
        Value::Object(map) => map.is_empty(),
        _ => false,
    };
    if !is_empty {
        return Err(AppError::BadRequest("Groups are not supported".to_string()));
    }
    Ok(Json(list_response(Vec::new())))
}

#[worker::send]
pub async fn org_billing_metadata(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_member(&db, &org_id, &claims.sub).await?;
    Ok(Json(json!({
        "object": "organizationBillingMetadata",
        "enabled": false
    })))
}

#[worker::send]
pub async fn list_org_events(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_member(&db, &org_id, &claims.sub).await?;
    Ok(Json(list_response(Vec::new())))
}

#[worker::send]
pub async fn list_org_compatibility_empty(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_member(&db, &org_id, &claims.sub).await?;
    Ok(Json(org_compatibility_empty_list()))
}

#[worker::send]
pub async fn org_subscription(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_member(&db, &org_id, &claims.sub).await?;
    Ok(Json(org_subscription_stub(&org_id)))
}

#[worker::send]
pub async fn unsupported_org_feature_mutation(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    ensure_org_admin(&db, &org_id, &claims.sub).await?;
    Err(AppError::BadRequest(
        "This organization feature is not supported".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::collection::CollectionDetails;
    use crate::models::organization::{
        ORG_USER_STATUS_CONFIRMED, ORG_USER_TYPE_ADMIN, ORG_USER_TYPE_MANAGER, ORG_USER_TYPE_OWNER,
        ORG_USER_TYPE_USER,
    };
    use serde_json::{json, Value};

    #[test]
    fn organization_profile_rows_map_to_profile_json_values() {
        let rows = vec![ProfileOrganizationRow {
            id: "org-1".into(),
            organization_user_id: "member-1".into(),
            user_id: "user-1".into(),
            name: "SSG".into(),
            key: Some("encrypted-key".into()),
            status: ORG_USER_STATUS_CONFIRMED,
            member_type: ORG_USER_TYPE_ADMIN,
            private_key: Some("private".into()),
            public_key: Some("public".into()),
        }];

        let values = profile_rows_to_json(rows);
        assert_eq!(values.len(), 1);
        assert_eq!(
            values[0]["object"],
            Value::String("profileOrganization".into())
        );
        assert_eq!(
            values[0]["organizationUserId"],
            Value::String("member-1".into())
        );
        assert_eq!(
            values[0]["permissions"]["editAnyCollection"],
            Value::Bool(true)
        );
        assert_eq!(values[0]["useGroups"], Value::Bool(false));
    }

    #[test]
    fn collections_json_array_serializes_collection_details() {
        let rows = vec![CollectionDetails {
            id: "collection-1".into(),
            organization_id: "org-1".into(),
            name: "Shared".into(),
            external_id: None,
            read_only: false,
            hide_passwords: false,
            manage: true,
        }];

        let json_array = collection_details_to_json_array(rows);
        let parsed: Value = serde_json::from_str(&json_array).unwrap();

        assert_eq!(
            parsed,
            json!([{
                "externalId": null,
                "hidePasswords": false,
                "id": "collection-1",
                "manage": true,
                "name": "Shared",
                "object": "collectionDetails",
                "organizationId": "org-1",
                "readOnly": false
            }])
        );
    }

    #[test]
    fn organization_details_json_includes_admin_capability_flags() {
        let details = OrganizationDetailsView {
            id: "org-1".into(),
            name: "SSG".into(),
            billing_email: Some("owner@ssg-healthcare.com".into()),
            private_key: Some("encrypted-private".into()),
            public_key: Some("public".into()),
            created_at: "2026-06-16T00:00:00.000Z".into(),
            updated_at: "2026-06-16T00:00:00.000Z".into(),
            member_id: Some("member-1".into()),
            member_type: Some(ORG_USER_TYPE_ADMIN),
        };

        let value = organization_details_json(&details);

        assert_eq!(value["object"], Value::String("organization".into()));
        assert_eq!(value["id"], Value::String("org-1".into()));
        assert_eq!(
            value["billingEmail"],
            Value::String("owner@ssg-healthcare.com".into())
        );
        assert_eq!(value["useGroups"], Value::Bool(false));
        assert_eq!(value["permissions"]["editAnyCollection"], Value::Bool(true));
        assert_eq!(value["permissions"]["manageUsers"], Value::Bool(true));
        assert_eq!(value["canCreateNewCollections"], Value::Bool(true));
        assert_eq!(value["canEditAllCiphers"], Value::Bool(true));
        assert_eq!(value["canEditAnyCollection"], Value::Bool(true));
        assert_eq!(
            value["allowAdminAccessToAllCollectionItems"],
            Value::Bool(true)
        );
    }

    #[test]
    fn organization_user_json_exposes_bitwarden_member_shape() {
        let member = OrganizationUserView {
            id: "member-1".into(),
            user_id: "user-1".into(),
            organization_id: "org-1".into(),
            name: Some("Member One".into()),
            email: "member@ssg-healthcare.com".into(),
            access_all: false,
            key: Some("encrypted-member-key".into()),
            status: ORG_USER_STATUS_CONFIRMED,
            member_type: 2,
            external_id: None,
            collections: vec![json!({
                "id": "collection-1",
                "readOnly": false,
                "hidePasswords": false,
                "manage": true
            })],
            created_at: "2026-06-16T00:00:00.000Z".into(),
            updated_at: "2026-06-16T00:00:00.000Z".into(),
        };

        let value = organization_user_json(&member);

        assert_eq!(value["object"], Value::String("organizationUser".into()));
        assert_eq!(value["id"], Value::String("member-1".into()));
        assert_eq!(value["userId"], Value::String("user-1".into()));
        assert_eq!(value["status"], Value::Number(2.into()));
        assert_eq!(value["accessAll"], Value::Bool(false));
        assert_eq!(
            value["collections"][0]["id"],
            Value::String("collection-1".into())
        );
    }

    #[test]
    fn organization_keys_json_exposes_private_key_aliases() {
        let value = organization_keys_json(Some("encrypted-private".into()), Some("public".into()));

        assert_eq!(value["object"], Value::String("organizationKeys".into()));
        assert_eq!(
            value["privateKey"],
            Value::String("encrypted-private".into())
        );
        assert_eq!(
            value["encryptedPrivateKey"],
            Value::String("encrypted-private".into())
        );
        assert_eq!(value["publicKey"], Value::String("public".into()));
    }

    #[test]
    fn org_compatibility_empty_list_uses_bitwarden_list_shape() {
        let value = org_compatibility_empty_list();

        assert_eq!(value["object"], Value::String("list".into()));
        assert_eq!(value["data"], Value::Array(Vec::new()));
        assert_eq!(value["continuationToken"], Value::Null);
    }

    #[test]
    fn org_subscription_stub_is_disabled_and_scoped_to_org() {
        let value = org_subscription_stub("org-1");

        assert_eq!(
            value["object"],
            Value::String("organizationSubscription".into())
        );
        assert_eq!(value["organizationId"], Value::String("org-1".into()));
        assert_eq!(value["enabled"], Value::Bool(false));
    }

    #[test]
    fn requested_member_type_rejects_invalid_roles() {
        let err = resolve_requested_member_type(Some(99), ORG_USER_TYPE_USER, ORG_USER_TYPE_OWNER)
            .unwrap_err();

        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn requested_owner_type_requires_owner_caller() {
        let err = resolve_requested_member_type(
            Some(ORG_USER_TYPE_OWNER),
            ORG_USER_TYPE_USER,
            ORG_USER_TYPE_ADMIN,
        )
        .unwrap_err();

        assert!(matches!(err, AppError::Forbidden(_)));
        assert_eq!(
            resolve_requested_member_type(
                Some(ORG_USER_TYPE_MANAGER),
                ORG_USER_TYPE_USER,
                ORG_USER_TYPE_OWNER,
            )
            .unwrap(),
            ORG_USER_TYPE_MANAGER
        );
    }

    #[test]
    fn last_confirmed_owner_cannot_be_removed() {
        let demote_err = ensure_owner_retained_after_member_change(
            ORG_USER_STATUS_CONFIRMED,
            ORG_USER_TYPE_OWNER,
            Some(ORG_USER_TYPE_ADMIN),
            1,
        )
        .unwrap_err();
        assert!(matches!(demote_err, AppError::Conflict(_)));

        let delete_err = ensure_owner_retained_after_member_change(
            ORG_USER_STATUS_CONFIRMED,
            ORG_USER_TYPE_OWNER,
            None,
            1,
        )
        .unwrap_err();
        assert!(matches!(delete_err, AppError::Conflict(_)));

        ensure_owner_retained_after_member_change(
            ORG_USER_STATUS_CONFIRMED,
            ORG_USER_TYPE_OWNER,
            Some(ORG_USER_TYPE_ADMIN),
            2,
        )
        .unwrap();
    }
}
