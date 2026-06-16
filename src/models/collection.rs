use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct CollectionDetails {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub external_id: Option<String>,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}

impl CollectionDetails {
    pub fn to_json(&self) -> Value {
        json!({
            "object": "collectionDetails",
            "id": self.id,
            "organizationId": self.organization_id,
            "name": self.name,
            "externalId": self.external_id,
            "readOnly": self.read_only,
            "hidePasswords": self.hide_passwords,
            "manage": self.manage
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionUserRequest {
    pub id: String,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub hide_passwords: bool,
    #[serde(default)]
    pub manage: bool,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionRequest {
    pub name: String,
    #[serde(default)]
    pub users: Vec<CollectionUserRequest>,
    #[serde(default)]
    pub groups: Vec<serde_json::Value>,
    pub external_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn collection_details_json_includes_acl_flags() {
        let collection = CollectionDetails {
            id: "collection-1".to_string(),
            organization_id: "org-1".to_string(),
            name: "Shared Logins".to_string(),
            external_id: None,
            read_only: true,
            hide_passwords: true,
            manage: false,
        };

        assert_eq!(
            collection.to_json(),
            json!({
                "object": "collectionDetails",
                "id": "collection-1",
                "organizationId": "org-1",
                "name": "Shared Logins",
                "externalId": null,
                "readOnly": true,
                "hidePasswords": true,
                "manage": false
            })
        );
    }
}
