use serde::Deserialize;
use serde_json::{json, Value};

#[allow(dead_code)]
pub const ORG_USER_STATUS_INVITED: i32 = 0;
#[allow(dead_code)]
pub const ORG_USER_STATUS_ACCEPTED: i32 = 1;
pub const ORG_USER_STATUS_CONFIRMED: i32 = 2;

pub const ORG_USER_TYPE_OWNER: i32 = 0;
pub const ORG_USER_TYPE_ADMIN: i32 = 1;
pub const ORG_USER_TYPE_USER: i32 = 2;
pub const ORG_USER_TYPE_MANAGER: i32 = 3;

pub fn is_org_admin_type(member_type: i32) -> bool {
    matches!(member_type, ORG_USER_TYPE_OWNER | ORG_USER_TYPE_ADMIN)
}

#[derive(Debug, Clone)]
pub struct ProfileOrganization {
    pub id: String,
    pub organization_user_id: String,
    pub user_id: String,
    pub name: String,
    pub key: String,
    pub status: i32,
    pub r#type: i32,
    pub has_public_and_private_keys: bool,
}

impl ProfileOrganization {
    pub fn to_json(&self) -> Value {
        let can_manage_collections = is_org_admin_type(self.r#type);
        json!({
            "object": "profileOrganization",
            "id": self.id,
            "organizationUserId": self.organization_user_id,
            "name": self.name,
            "userId": self.user_id,
            "key": self.key,
            "status": self.status,
            "type": self.r#type,
            "enabled": true,
            "useTotp": true,
            "usersGetPremium": true,
            "hasPublicAndPrivateKeys": self.has_public_and_private_keys,
            "usePolicies": true,
            "useGroups": false,
            "useSso": false,
            "permissions": {
                "createNewCollections": can_manage_collections,
                "editAnyCollection": can_manage_collections,
                "deleteAnyCollection": can_manage_collections
            },
            "limitCollectionCreation": !can_manage_collections,
            "limitCollectionDeletion": !can_manage_collections
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationKeysRequest {
    pub encrypted_private_key: String,
    pub public_key: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub billing_email: Option<String>,
    pub collection_name: String,
    pub key: String,
    pub keys: Option<OrganizationKeysRequest>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn profile_organization_json_matches_bitwarden_shape() {
        let org = ProfileOrganization {
            id: "org-1".to_string(),
            organization_user_id: "member-1".to_string(),
            user_id: "user-1".to_string(),
            name: "SSG".to_string(),
            key: "encrypted-org-key".to_string(),
            status: ORG_USER_STATUS_CONFIRMED,
            r#type: ORG_USER_TYPE_OWNER,
            has_public_and_private_keys: true,
        };

        assert_eq!(
            org.to_json(),
            json!({
                "object": "profileOrganization",
                "id": "org-1",
                "organizationUserId": "member-1",
                "name": "SSG",
                "userId": "user-1",
                "key": "encrypted-org-key",
                "status": 2,
                "type": 0,
                "enabled": true,
                "useTotp": true,
                "usersGetPremium": true,
                "hasPublicAndPrivateKeys": true,
                "usePolicies": true,
                "useGroups": false,
                "useSso": false,
                "permissions": {
                    "createNewCollections": true,
                    "editAnyCollection": true,
                    "deleteAnyCollection": true
                },
                "limitCollectionCreation": false,
                "limitCollectionDeletion": false
            })
        );
    }

    #[test]
    fn member_type_helpers_identify_admin_roles() {
        assert!(is_org_admin_type(ORG_USER_TYPE_OWNER));
        assert!(is_org_admin_type(ORG_USER_TYPE_ADMIN));
        assert!(!is_org_admin_type(ORG_USER_TYPE_USER));
        assert!(!is_org_admin_type(ORG_USER_TYPE_MANAGER));
    }
}
