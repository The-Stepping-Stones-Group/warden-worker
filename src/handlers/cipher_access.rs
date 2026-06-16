use serde::Deserialize;

use crate::{
    db::Db,
    error::AppError,
    models::organization::{
        is_org_admin_type, ORG_USER_STATUS_CONFIRMED, ORG_USER_TYPE_ADMIN, ORG_USER_TYPE_OWNER,
    },
};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct CipherAccessView {
    pub cipher_id: String,
    pub owner_user_id: Option<String>,
    pub organization_id: Option<String>,
    pub collection_ids: Vec<String>,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
    pub member_type: Option<i32>,
    pub access_all: bool,
}

impl CipherAccessView {
    pub fn can_edit(&self) -> bool {
        self.organization_id.is_none()
            || self.access_all
            || self.member_type.map(is_org_admin_type).unwrap_or(false)
            || !self.read_only
    }

    pub fn can_delete_or_restore(&self) -> bool {
        self.can_edit()
    }

    #[allow(dead_code)]
    pub fn can_view_password(&self) -> bool {
        self.organization_id.is_none()
            || self.access_all
            || self.member_type.map(is_org_admin_type).unwrap_or(false)
            || !self.hide_passwords
    }

    #[allow(dead_code)]
    pub fn collection_json_array(&self) -> String {
        serde_json::to_string(&self.collection_ids).unwrap_or_else(|_| "[]".to_string())
    }
}

#[derive(Debug, Deserialize)]
struct CipherAccessRow {
    cipher_id: String,
    owner_user_id: Option<String>,
    organization_id: Option<String>,
    collection_ids: Option<String>,
    read_only: i32,
    hide_passwords: i32,
    manage: i32,
    member_type: Option<i32>,
    access_all: i32,
}

impl CipherAccessRow {
    fn into_view(self) -> CipherAccessView {
        let collection_ids = self
            .collection_ids
            .as_deref()
            .and_then(|ids| serde_json::from_str::<Vec<String>>(ids).ok())
            .unwrap_or_default();

        CipherAccessView {
            cipher_id: self.cipher_id,
            owner_user_id: self.owner_user_id,
            organization_id: self.organization_id,
            collection_ids,
            read_only: self.read_only != 0,
            hide_passwords: self.hide_passwords != 0,
            manage: self.manage != 0,
            member_type: self.member_type,
            access_all: self.access_all != 0,
        }
    }
}

#[allow(dead_code)]
pub(crate) async fn get_cipher_access_view(
    db: &Db,
    cipher_id: &str,
    user_id: &str,
) -> Result<Option<CipherAccessView>, AppError> {
    let row: Option<CipherAccessRow> = db
        .prepare(
            "SELECT \
                c.id AS cipher_id, \
                c.user_id AS owner_user_id, \
                c.organization_id, \
                COALESCE(( \
                    SELECT json_group_array(cc.collection_id) \
                    FROM ciphers_collections cc \
                    WHERE cc.cipher_id = c.id \
                ), '[]') AS collection_ids, \
                CASE \
                    WHEN c.organization_id IS NULL THEN 0 \
                    WHEN uo.access_all = 1 OR uo.type IN (?3, ?4) THEN 0 \
                    ELSE COALESCE(( \
                        SELECT MIN(uc.read_only) \
                        FROM ciphers_collections cc \
                        JOIN users_collections uc ON uc.collection_id = cc.collection_id \
                        WHERE cc.cipher_id = c.id AND uc.user_id = ?2 \
                    ), 1) \
                END AS read_only, \
                CASE \
                    WHEN c.organization_id IS NULL THEN 0 \
                    WHEN uo.access_all = 1 OR uo.type IN (?3, ?4) THEN 0 \
                    ELSE COALESCE(( \
                        SELECT MIN(uc.hide_passwords) \
                        FROM ciphers_collections cc \
                        JOIN users_collections uc ON uc.collection_id = cc.collection_id \
                        WHERE cc.cipher_id = c.id AND uc.user_id = ?2 \
                    ), 0) \
                END AS hide_passwords, \
                CASE \
                    WHEN c.organization_id IS NULL THEN 1 \
                    WHEN uo.access_all = 1 OR uo.type IN (?3, ?4) THEN 1 \
                    ELSE COALESCE(( \
                        SELECT MAX(uc.manage) \
                        FROM ciphers_collections cc \
                        JOIN users_collections uc ON uc.collection_id = cc.collection_id \
                        WHERE cc.cipher_id = c.id AND uc.user_id = ?2 \
                    ), 0) \
                END AS manage, \
                uo.type AS member_type, \
                COALESCE(uo.access_all, 0) AS access_all \
             FROM ciphers c \
             LEFT JOIN users_organizations uo \
                ON uo.organization_id = c.organization_id \
                AND uo.user_id = ?2 \
                AND uo.status = ?5 \
             WHERE c.id = ?1 \
                AND ( \
                    (c.organization_id IS NULL AND c.user_id = ?2) \
                    OR ( \
                        c.organization_id IS NOT NULL \
                        AND uo.id IS NOT NULL \
                        AND ( \
                            uo.access_all = 1 \
                            OR uo.type IN (?3, ?4) \
                            OR EXISTS ( \
                                SELECT 1 \
                                FROM ciphers_collections cc \
                                JOIN users_collections uc ON uc.collection_id = cc.collection_id \
                                WHERE cc.cipher_id = c.id AND uc.user_id = ?2 \
                            ) \
                        ) \
                    ) \
                )",
        )
        .bind(&[
            cipher_id.into(),
            user_id.into(),
            ORG_USER_TYPE_OWNER.into(),
            ORG_USER_TYPE_ADMIN.into(),
            ORG_USER_STATUS_CONFIRMED.into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    Ok(row.map(CipherAccessRow::into_view))
}

#[allow(dead_code)]
pub(crate) async fn ensure_cipher_read(
    db: &Db,
    cipher_id: &str,
    user_id: &str,
) -> Result<CipherAccessView, AppError> {
    get_cipher_access_view(db, cipher_id, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))
}

#[allow(dead_code)]
pub(crate) async fn ensure_cipher_write(
    db: &Db,
    cipher_id: &str,
    user_id: &str,
) -> Result<CipherAccessView, AppError> {
    let view = ensure_cipher_read(db, cipher_id, user_id).await?;
    if view.can_edit() {
        Ok(view)
    } else {
        Err(AppError::Forbidden(
            "You do not have permission to edit this cipher".to_string(),
        ))
    }
}

#[allow(dead_code)]
pub(crate) async fn ensure_cipher_delete(
    db: &Db,
    cipher_id: &str,
    user_id: &str,
) -> Result<CipherAccessView, AppError> {
    let view = ensure_cipher_read(db, cipher_id, user_id).await?;
    if view.can_delete_or_restore() {
        Ok(view)
    } else {
        Err(AppError::Forbidden(
            "You do not have permission to delete this cipher".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::organization::{ORG_USER_TYPE_OWNER, ORG_USER_TYPE_USER};

    #[test]
    fn collection_acl_maps_to_cipher_permissions() {
        let view = CipherAccessView {
            cipher_id: "cipher-1".into(),
            owner_user_id: Some("owner".into()),
            organization_id: Some("org-1".into()),
            collection_ids: vec!["collection-1".into()],
            read_only: true,
            hide_passwords: true,
            manage: false,
            member_type: Some(ORG_USER_TYPE_USER),
            access_all: false,
        };

        assert!(!view.can_edit());
        assert!(!view.can_delete_or_restore());
        assert!(!view.can_view_password());
    }

    #[test]
    fn owner_membership_can_manage_org_cipher() {
        let view = CipherAccessView {
            cipher_id: "cipher-1".into(),
            owner_user_id: Some("owner".into()),
            organization_id: Some("org-1".into()),
            collection_ids: vec![],
            read_only: true,
            hide_passwords: true,
            manage: false,
            member_type: Some(ORG_USER_TYPE_OWNER),
            access_all: true,
        };

        assert!(view.can_edit());
        assert!(view.can_delete_or_restore());
        assert!(view.can_view_password());
    }
}
