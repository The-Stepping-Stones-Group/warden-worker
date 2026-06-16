use serde::Deserialize;
use serde_json::Value;

use crate::{
    db::Db,
    error::AppError,
    models::organization::{
        is_org_admin_type, ProfileOrganization, ORG_USER_STATUS_ACCEPTED, ORG_USER_STATUS_CONFIRMED,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::organization::{ORG_USER_STATUS_CONFIRMED, ORG_USER_TYPE_ADMIN};
    use serde_json::Value;

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
}
