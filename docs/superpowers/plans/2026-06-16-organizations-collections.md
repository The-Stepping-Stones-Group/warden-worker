# Organizations and Collections Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Bitwarden-compatible organization and collection support for Warden Worker, including schema, routes, sync/profile output, access control, attachments, deployment, and live shared-vault proof.

**Architecture:** Add organization, membership, collection, ACL, and cipher assignment tables, then route all shared-vault behavior through small repository/access helpers. Keep encrypted values opaque, reuse existing D1/session patterns, and update sync/cipher JSON construction so personal vault behavior remains unchanged while org ciphers become visible through confirmed membership and collection permissions.

**Tech Stack:** Rust 2021, Cloudflare Workers, Axum, Cloudflare D1, Wrangler, serde/serde_json, uuid, chrono, existing Worker unit-test harness.

---

## File Map

- Create `migrations/0014_add_organizations_collections.sql`: live D1 migration for org, membership, collection, ACL, and cipher assignment tables and indexes.
- Modify `sql/schema.sql`: include the same tables and indexes for fresh deployments.
- Create `src/models/organization.rs`: organization/member constants, request bodies, and Bitwarden JSON response builders.
- Create `src/models/collection.rs`: collection request bodies and collection details JSON response builders.
- Modify `src/models/mod.rs`: export `organization` and `collection`.
- Create `src/handlers/organizations.rs`: org CRUD, key/public-key, collection, member, and compatibility handlers.
- Create `src/handlers/cipher_access.rs`: shared cipher visibility and permission queries for personal and org ciphers.
- Modify `src/handlers/mod.rs`: export new handlers.
- Modify `src/router.rs`: mount organization, collection, and cipher sharing routes.
- Modify `src/models/sync.rs`: allow profile organizations to be populated from DB.
- Modify `src/handlers/accounts.rs`: include org profile data in `/api/accounts/profile`.
- Modify `src/handlers/sync.rs`: append org collections and visible org ciphers.
- Modify `src/handlers/ciphers.rs`: persist collection assignments, implement share/collection routes, and use access helper for read/update/delete/list paths.
- Modify `src/handlers/import.rs`: validate org and collection assignments on imports.
- Modify `src/handlers/attachments.rs`: replace personal-only attachment auth with the shared cipher access helper.
- Modify `src/handlers/streaming.rs`: use the shared attachment/cipher auth for streaming upload/download tokens.
- Modify `src/handlers/purge.rs` and account key rotation paths in `src/handlers/accounts.rs`: preserve org ciphers and validate org attachment handling.
- Modify `src/notifications.rs` and `src/push.rs`: populate org and collection IDs where the caller knows them.
- Create `scripts/live-org-proof.sh`: redacted live verifier for deploy proof using two SSG-domain accounts.
- Modify `README.md`: move Organizations/Sharing from unsupported to supported-with-scope and document excluded enterprise features.

## Task 1: Schema and Pure Model Foundations

**Files:**
- Create: `migrations/0014_add_organizations_collections.sql`
- Modify: `sql/schema.sql`
- Create: `src/models/organization.rs`
- Create: `src/models/collection.rs`
- Modify: `src/models/mod.rs`

- [ ] **Step 1: Write failing schema/model tests**

Add unit tests inside `src/models/organization.rs` and `src/models/collection.rs` before production code exists:

```rust
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
```

```rust
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
```

- [ ] **Step 2: Verify the tests fail for missing model files**

Run:

```bash
cargo test --locked organization collection --lib
```

Expected: fail because `src/models/organization.rs` and `src/models/collection.rs` are missing or unexported.

- [ ] **Step 3: Add the migration and base schema**

Create `migrations/0014_add_organizations_collections.sql` with:

```sql
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    billing_email TEXT,
    private_key TEXT,
    public_key TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users_organizations (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    invited_by_email TEXT,
    access_all INTEGER NOT NULL DEFAULT 0,
    key TEXT,
    status INTEGER NOT NULL,
    type INTEGER NOT NULL,
    reset_password_key TEXT,
    external_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    UNIQUE(user_id, organization_id)
);

CREATE INDEX IF NOT EXISTS idx_users_organizations_user_id
    ON users_organizations(user_id);
CREATE INDEX IF NOT EXISTS idx_users_organizations_organization_id
    ON users_organizations(organization_id);

CREATE TABLE IF NOT EXISTS collections (
    id TEXT PRIMARY KEY NOT NULL,
    organization_id TEXT NOT NULL,
    name TEXT NOT NULL,
    external_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_collections_organization_id
    ON collections(organization_id);

CREATE TABLE IF NOT EXISTS users_collections (
    user_id TEXT NOT NULL,
    collection_id TEXT NOT NULL,
    read_only INTEGER NOT NULL DEFAULT 0,
    hide_passwords INTEGER NOT NULL DEFAULT 0,
    manage INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, collection_id)
);

CREATE INDEX IF NOT EXISTS idx_users_collections_collection_id
    ON users_collections(collection_id);

CREATE TABLE IF NOT EXISTS ciphers_collections (
    cipher_id TEXT NOT NULL,
    collection_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE,
    FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE,
    PRIMARY KEY (cipher_id, collection_id)
);

CREATE INDEX IF NOT EXISTS idx_ciphers_collections_collection_id
    ON ciphers_collections(collection_id);
CREATE INDEX IF NOT EXISTS idx_ciphers_organization_id
    ON ciphers(organization_id);
```

Append the same table and index definitions to `sql/schema.sql` after the `ciphers` table and before attachments.

- [ ] **Step 4: Add pure response/request models**

Create `src/models/organization.rs` with constants, request bodies, and pure JSON builders:

```rust
use serde::Deserialize;
use serde_json::{json, Value};

pub const ORG_USER_STATUS_INVITED: i32 = 0;
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationKeysRequest {
    pub encrypted_private_key: String,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub billing_email: Option<String>,
    pub collection_name: String,
    pub key: String,
    pub keys: Option<OrganizationKeysRequest>,
}
```

Create `src/models/collection.rs` with:

```rust
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
```

Export both modules in `src/models/mod.rs`.

- [ ] **Step 5: Verify green**

Run:

```bash
cargo test --locked organization collection --lib
cargo fmt -- --check
```

Expected: the new model tests pass and formatting is clean.

- [ ] **Step 6: Commit**

```bash
git add migrations/0014_add_organizations_collections.sql sql/schema.sql src/models/mod.rs src/models/organization.rs src/models/collection.rs
git commit -m "feat: add organization collection schema models"
```

## Task 2: Organization Repository and Profile Data

**Files:**
- Create: `src/handlers/organizations.rs`
- Modify: `src/handlers/mod.rs`
- Modify: `src/models/sync.rs`
- Modify: `src/handlers/accounts.rs`

- [ ] **Step 1: Write failing profile organization tests**

Add pure tests in `src/handlers/organizations.rs` for SQL row mapping:

```rust
#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(values[0]["object"], Value::String("profileOrganization".into()));
        assert_eq!(values[0]["organizationUserId"], Value::String("member-1".into()));
        assert_eq!(values[0]["permissions"]["editAnyCollection"], Value::Bool(true));
        assert_eq!(values[0]["useGroups"], Value::Bool(false));
    }
}
```

- [ ] **Step 2: Verify red**

Run:

```bash
cargo test --locked organization_profile_rows_map_to_profile_json_values --lib
```

Expected: fail because `ProfileOrganizationRow` and `profile_rows_to_json` do not exist.

- [ ] **Step 3: Add repository/profile helpers**

In `src/handlers/organizations.rs`, add:

```rust
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    db::Db,
    error::AppError,
    models::organization::{
        is_org_admin_type, ProfileOrganization, ORG_USER_STATUS_ACCEPTED,
        ORG_USER_STATUS_CONFIRMED, ORG_USER_TYPE_ADMIN, ORG_USER_TYPE_OWNER,
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
```

Also add an `admin_membership_for_org` helper:

```rust
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

impl OrganizationMembershipRow {
    pub fn is_confirmed(&self) -> bool {
        self.status == ORG_USER_STATUS_CONFIRMED
    }

    pub fn is_admin(&self) -> bool {
        self.is_confirmed() && is_org_admin_type(self.member_type)
    }
}
```

- [ ] **Step 4: Wire profile endpoint**

Change `Profile::from_user` to keep the existing empty organizations default. In `accounts::get_profile`, after creating the profile, call `organizations::profile_organizations_for_user(&db, &claims.sub).await?` and assign it to `profile.organizations`.

- [ ] **Step 5: Verify green**

Run:

```bash
cargo test --locked organization_profile_rows_map_to_profile_json_values --lib
cargo test --locked --lib
cargo fmt -- --check
```

Expected: profile helper test and existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/handlers/organizations.rs src/handlers/mod.rs src/models/sync.rs src/handlers/accounts.rs
git commit -m "feat: add organization profile helpers"
```

## Task 3: Cipher Access Helper

**Files:**
- Create: `src/handlers/cipher_access.rs`
- Modify: `src/handlers/mod.rs`

- [ ] **Step 1: Write failing permission tests**

Add tests in `src/handlers/cipher_access.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

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
```

- [ ] **Step 2: Verify red**

Run:

```bash
cargo test --locked collection_acl_maps_to_cipher_permissions owner_membership_can_manage_org_cipher --lib
```

Expected: fail because `CipherAccessView` does not exist.

- [ ] **Step 3: Implement pure access type and query entry points**

Add `CipherAccessView`, permission methods, and async functions:

```rust
use serde::Deserialize;

use crate::{
    db::Db,
    error::AppError,
    models::organization::{
        is_org_admin_type, ORG_USER_STATUS_CONFIRMED, ORG_USER_TYPE_OWNER,
    },
};

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

    pub fn can_view_password(&self) -> bool {
        self.organization_id.is_none()
            || self.access_all
            || self.member_type.map(is_org_admin_type).unwrap_or(false)
            || !self.hide_passwords
    }

    pub fn collection_json_array(&self) -> String {
        serde_json::to_string(&self.collection_ids).unwrap_or_else(|_| "[]".to_string())
    }
}
```

Add async query functions named `get_cipher_access_view`, `ensure_cipher_read`,
`ensure_cipher_write`, and `ensure_cipher_delete`. They must return `404` for no
visible row and `403` for visible but read-only mutation attempts. The SQL joins
`ciphers`, `users_organizations`, `ciphers_collections`, and `users_collections`,
and personal rows match `c.user_id = ?user_id AND c.organization_id IS NULL`.

- [ ] **Step 4: Verify green**

Run:

```bash
cargo test --locked collection_acl_maps_to_cipher_permissions owner_membership_can_manage_org_cipher --lib
cargo fmt -- --check
```

Expected: access tests pass and formatting is clean.

- [ ] **Step 5: Commit**

```bash
git add src/handlers/cipher_access.rs src/handlers/mod.rs
git commit -m "feat: add shared cipher access helper"
```

## Task 4: Sync Collections and Visible Org Ciphers

**Files:**
- Modify: `src/handlers/organizations.rs`
- Modify: `src/handlers/sync.rs`
- Modify: `src/handlers/ciphers.rs`

- [ ] **Step 1: Write failing JSON SQL tests**

Add pure tests in `src/handlers/ciphers.rs` for SQL expression content:

```rust
#[test]
fn cipher_json_expression_uses_access_aliases_for_org_permissions() {
    let sql = cipher_json_expr(false);
    assert!(sql.contains("'collectionIds'"));
    assert!(sql.contains("json_group_array"));
    assert!(sql.contains("'edit'"));
    assert!(sql.contains("'viewPassword'"));
}
```

Add a pure collection aggregation test in `src/handlers/organizations.rs`:

```rust
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
    let json = collection_details_to_json_array(rows);
    assert_eq!(json, "[{\"externalId\":null,\"hidePasswords\":false,\"id\":\"collection-1\",\"manage\":true,\"name\":\"Shared\",\"object\":\"collectionDetails\",\"organizationId\":\"org-1\",\"readOnly\":false}]");
}
```

- [ ] **Step 2: Verify red**

Run:

```bash
cargo test --locked cipher_json_expression_uses_access_aliases_for_org_permissions collections_json_array_serializes_collection_details --lib
```

Expected: fail because collection aggregation and SQL expression changes are absent.

- [ ] **Step 3: Add visible collection JSON helper**

In `organizations.rs`, add `visible_collections_for_user_json(db, user_id)` that queries confirmed memberships and collection ACL rows, then serializes `Vec<CollectionDetails>` into a JSON array string using `to_json()`.

- [ ] **Step 4: Update sync assembly**

In `sync.rs`, compute:

```rust
let collections_json = organizations::visible_collections_for_user_json(&db, &user_id).await?;
```

Replace the hard-coded `,"collections":[]` with `,"collections":` followed by `collections_json`, keep `,"policies":[]`, and change cipher append to a new visible-cipher where clause that includes personal rows and org rows through confirmed membership/collection ACL.

- [ ] **Step 5: Update cipher JSON expression**

Change `cipher_json_expr` so `collectionIds` is built from `ciphers_collections`, and `edit`, `viewPassword`, and `permissions` can be calculated when the query aliases access columns. The expression must still work for personal-only list routes.

- [ ] **Step 6: Verify green**

Run:

```bash
cargo test --locked cipher_json_expression_uses_access_aliases_for_org_permissions collections_json_array_serializes_collection_details --lib
cargo test --locked --lib
cargo fmt -- --check
```

Expected: all local tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/handlers/organizations.rs src/handlers/sync.rs src/handlers/ciphers.rs
git commit -m "feat: sync organization collections and ciphers"
```

## Task 5: Organization and Collection Routes

**Files:**
- Modify: `src/handlers/organizations.rs`
- Modify: `src/router.rs`

- [ ] **Step 1: Write failing request/response tests**

Add tests in `src/models/organization.rs` and `src/models/collection.rs` for request aliases and route response builders:

```rust
#[test]
fn create_org_request_accepts_bitwarden_payload() {
    let body = r#"{
        "name":"SSG",
        "billingEmail":"owner@ssg-healthcare.com",
        "collectionName":"Default",
        "key":"encrypted-key",
        "keys":{"encryptedPrivateKey":"encrypted-private","publicKey":"public"}
    }"#;

    let parsed: CreateOrganizationRequest = serde_json::from_str(body).unwrap();
    assert_eq!(parsed.name, "SSG");
    assert_eq!(parsed.collection_name, "Default");
    assert_eq!(parsed.keys.unwrap().public_key, "public");
}
```

```rust
#[test]
fn collection_request_accepts_users_and_groups_arrays() {
    let body = r#"{
        "name":"Shared",
        "users":[{"id":"member-1","readOnly":true,"hidePasswords":false,"manage":true}],
        "groups":[],
        "externalId":null
    }"#;

    let parsed: CollectionRequest = serde_json::from_str(body).unwrap();
    assert_eq!(parsed.name, "Shared");
    assert_eq!(parsed.users[0].id, "member-1");
    assert!(parsed.users[0].read_only);
}
```

- [ ] **Step 2: Verify red or partial red**

Run:

```bash
cargo test --locked create_org_request_accepts_bitwarden_payload collection_request_accepts_users_and_groups_arrays --lib
```

Expected: fail if request structs do not yet deserialize the payload exactly.

- [ ] **Step 3: Implement org CRUD, keys, collections, members**

In `organizations.rs`, implement handlers for the routes listed in the design:

- `create_organization`: insert org, owner membership, default collection, owner collection ACL, return organization details JSON.
- `get_organization`: admin/member visible org details.
- `update_organization`: admin-only name/billing update.
- `post_organization_keys`, `get_organization_keys`, `get_organization_public_key`.
- `list_org_collections`, `list_org_collections_details`, `create_collection`, `update_collection`, `delete_collection`.
- `list_all_collections`: calls visible collection helper and wraps list shape when required.
- `list_org_users`, `invite_org_users`, `accept_org_user`, `confirm_org_user`, `confirm_org_users`, `get_org_user`, `update_org_user`, `delete_org_user`, `post_org_users_public_keys`.
- compatibility handlers returning empty arrays/objects for policies, groups, billing, and events probes observed in manual web-vault testing.

All admin routes call the admin membership helper. Member-visible routes call confirmed or accepted membership helpers.

- [ ] **Step 4: Mount routes**

Add organization and collection routes in `router.rs` near the sync/profile routes and before ciphers where path specificity matters.

- [ ] **Step 5: Verify green**

Run:

```bash
cargo test --locked create_org_request_accepts_bitwarden_payload collection_request_accepts_users_and_groups_arrays --lib
cargo test --locked --lib
cargo fmt -- --check
```

Expected: tests pass and router compiles.

- [ ] **Step 6: Commit**

```bash
git add src/models/organization.rs src/models/collection.rs src/handlers/organizations.rs src/router.rs
git commit -m "feat: add organization collection routes"
```

## Task 6: Cipher Sharing and Collection Assignment

**Files:**
- Modify: `src/models/cipher.rs`
- Modify: `src/handlers/ciphers.rs`
- Modify: `src/handlers/import.rs`
- Modify: `src/router.rs`

- [ ] **Step 1: Write failing collection assignment tests**

Add pure tests in `src/handlers/ciphers.rs`:

```rust
#[test]
fn normalize_collection_ids_removes_duplicates_and_empty_values() {
    let ids = normalize_collection_ids(vec![
        "collection-2".into(),
        "".into(),
        "collection-1".into(),
        "collection-2".into(),
    ]);

    assert_eq!(ids, vec!["collection-1".to_string(), "collection-2".to_string()]);
}
```

- [ ] **Step 2: Verify red**

Run:

```bash
cargo test --locked normalize_collection_ids_removes_duplicates_and_empty_values --lib
```

Expected: fail because `normalize_collection_ids` does not exist.

- [ ] **Step 3: Implement collection assignment helpers**

In `ciphers.rs`, add helpers:

- `normalize_collection_ids(Vec<String>) -> Vec<String>`
- `validate_collections_for_org(db, org_id, collection_ids) -> Result<(), AppError>`
- `replace_cipher_collections(db, cipher_id, collection_ids, now) -> Result<(), AppError>`

Use `DELETE FROM ciphers_collections WHERE cipher_id = ?1` followed by batch inserts.

- [ ] **Step 4: Update create/update/share paths**

Update `create_cipher`, `create_cipher_simple`, `update_cipher`, import, and new share routes so:

- personal ciphers require empty collection IDs and `organization_id IS NULL`;
- org ciphers require a valid org and all collection IDs in that org;
- owner/admin or writable collection permissions are required;
- `ciphers_collections` is persisted on create/share/update;
- returned `Cipher` includes collection IDs and permission booleans.

- [ ] **Step 5: Mount cipher share routes**

Add routes:

```rust
.route("/api/ciphers/{id}/share", post(ciphers::share_cipher).put(ciphers::share_cipher))
.route("/api/ciphers/{id}/collections", post(ciphers::put_cipher_collections).put(ciphers::put_cipher_collections))
.route("/api/ciphers/{id}/collections_v2", post(ciphers::put_cipher_collections).put(ciphers::put_cipher_collections))
```

- [ ] **Step 6: Verify green**

Run:

```bash
cargo test --locked normalize_collection_ids_removes_duplicates_and_empty_values --lib
cargo test --locked --lib
cargo fmt -- --check
```

Expected: all local tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/models/cipher.rs src/handlers/ciphers.rs src/handlers/import.rs src/router.rs
git commit -m "feat: persist organization cipher sharing"
```

## Task 7: Replace Personal-Only Cipher Authorization

**Files:**
- Modify: `src/handlers/ciphers.rs`
- Modify: `src/handlers/accounts.rs`
- Modify: `src/handlers/purge.rs`

- [ ] **Step 1: Write failing access replacement tests**

Add a pure SQL test in `src/handlers/ciphers.rs`:

```rust
#[test]
fn visible_cipher_where_clause_includes_personal_and_org_access() {
    let clause = visible_cipher_where_clause();
    assert!(clause.contains("c.organization_id IS NULL"));
    assert!(clause.contains("users_organizations"));
    assert!(clause.contains("users_collections"));
    assert!(clause.contains("ciphers_collections"));
}
```

- [ ] **Step 2: Verify red**

Run:

```bash
cargo test --locked visible_cipher_where_clause_includes_personal_and_org_access --lib
```

Expected: fail because `visible_cipher_where_clause` does not exist.

- [ ] **Step 3: Replace direct `c.user_id = ?` access paths**

Update all cipher read/write/delete/list/archive/restore/bulk/move paths to use `cipher_access` helpers or visible SQL. Preserve personal folder validation. Reject folder assignment for org ciphers because folders are personal.

- [ ] **Step 4: Keep account rotation personal-only by design**

Update key rotation validation comments and queries so it explicitly rotates only personal ciphers and leaves org ciphers to org sharing flows. Do not silently mutate org ciphers during personal key rotation.

- [ ] **Step 5: Verify green**

Run:

```bash
cargo test --locked visible_cipher_where_clause_includes_personal_and_org_access --lib
cargo test --locked --lib
cargo fmt -- --check
```

Expected: all local tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/handlers/ciphers.rs src/handlers/accounts.rs src/handlers/purge.rs
git commit -m "feat: enforce organization cipher access"
```

## Task 8: Organization Attachments

**Files:**
- Modify: `src/handlers/attachments.rs`
- Modify: `src/handlers/streaming.rs`
- Modify: `src/handlers/cipher_access.rs`

- [ ] **Step 1: Write failing attachment permission tests**

Add pure tests in `src/handlers/cipher_access.rs`:

```rust
#[test]
fn read_only_member_can_download_but_not_upload_attachment() {
    let view = CipherAccessView {
        cipher_id: "cipher-1".into(),
        owner_user_id: Some("owner".into()),
        organization_id: Some("org-1".into()),
        collection_ids: vec!["collection-1".into()],
        read_only: true,
        hide_passwords: false,
        manage: false,
        member_type: Some(ORG_USER_TYPE_USER),
        access_all: false,
    };

    assert!(view.can_read_attachment());
    assert!(!view.can_write_attachment());
}
```

- [ ] **Step 2: Verify red**

Run:

```bash
cargo test --locked read_only_member_can_download_but_not_upload_attachment --lib
```

Expected: fail because attachment permission methods do not exist.

- [ ] **Step 3: Replace `ensure_cipher_for_user` behavior**

Change attachment auth so it accepts personal ciphers and org ciphers visible through the shared helper. Remove the `"Organization attachments are not supported"` rejection. Store pending and finalized `organization_id` from the cipher row.

- [ ] **Step 4: Update streaming upload/download**

Use `ensure_cipher_read` for downloads and `ensure_cipher_write` for uploads/finalization. Keep token claim checks unchanged.

- [ ] **Step 5: Verify green**

Run:

```bash
cargo test --locked read_only_member_can_download_but_not_upload_attachment --lib
cargo test --locked --lib
cargo fmt -- --check
```

Expected: all local tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/handlers/attachments.rs src/handlers/streaming.rs src/handlers/cipher_access.rs
git commit -m "feat: allow organization attachments with access checks"
```

## Task 9: Notifications, Compatibility Stubs, and Docs

**Files:**
- Modify: `src/notifications.rs`
- Modify: `src/push.rs`
- Modify: `src/handlers/organizations.rs`
- Modify: `README.md`

- [ ] **Step 1: Write failing notification shape tests**

Add pure tests in `src/notifications.rs` or `src/push.rs` around any existing notification JSON helper:

```rust
#[test]
fn cipher_notification_can_include_org_and_collection_ids() {
    let payload = build_cipher_update_payload_for_test(
        "cipher-1",
        Some("org-1"),
        vec!["collection-1".to_string()],
    );
    assert_eq!(payload["organizationId"], "org-1");
    assert_eq!(payload["collectionIds"][0], "collection-1");
}
```

- [ ] **Step 2: Verify red**

Run:

```bash
cargo test --locked cipher_notification_can_include_org_and_collection_ids --lib
```

Expected: fail because the test helper or org fields do not exist.

- [ ] **Step 3: Populate known org fields**

Update notification/push helpers so cipher routes that know organization and collection IDs can pass them through. Preserve null fields for personal ciphers.

- [ ] **Step 4: Add compatibility route bodies**

Add empty/default handlers in `organizations.rs` for observed web-vault probes:

```json
{"data":[],"object":"list","continuationToken":null}
```

for list-shaped features and:

```json
{"object":"organizationBillingMetadata","enabled":false}
```

for billing metadata probes that require an object response.

- [ ] **Step 5: Update README**

Move Organizations, Sharing, and Collections into the supported list with a scoped note. Keep Groups, SSO, SCIM, billing, providers, and enterprise policy enforcement in unsupported/limited.

- [ ] **Step 6: Verify green**

Run:

```bash
cargo test --locked cipher_notification_can_include_org_and_collection_ids --lib
cargo test --locked --lib
cargo fmt -- --check
```

Expected: all tests and formatting pass.

- [ ] **Step 7: Commit**

```bash
git add src/notifications.rs src/push.rs src/handlers/organizations.rs README.md
git commit -m "feat: add organization compatibility surfaces"
```

## Task 10: Local Full Verification

**Files:**
- Modify only if tests reveal a real defect.

- [ ] **Step 1: Run full local test suite**

```bash
cargo test --locked
```

Expected: all tests pass.

- [ ] **Step 2: Run formatting check**

```bash
cargo fmt -- --check
```

Expected: no formatting diff.

- [ ] **Step 3: Run Wrangler dry-run build**

```bash
npx wrangler deploy --dry-run --outdir build/dry-run
```

Expected: Worker builds successfully.

- [ ] **Step 4: Commit fixes if required**

If a verifier fails, write the smallest failing test that captures the defect, fix it, rerun the failing verifier, rerun the full local verification, then commit with a message naming the defect.

## Task 11: Live Cloudflare Migration, Deploy, and Proof

**Files:**
- Create: `scripts/live-org-proof.sh`
- Modify: `docs/deployment.md`

- [ ] **Step 1: Add redacted live proof script**

Create `scripts/live-org-proof.sh` that:

- sources `../.env.local` without printing secrets;
- exports Cloudflare account env vars;
- accepts `WARDEN_PROOF_USER_A_EMAIL`, `WARDEN_PROOF_USER_A_PASSWORD`, `WARDEN_PROOF_USER_B_EMAIL`, and `WARDEN_PROOF_USER_B_PASSWORD`;
- logs only HTTP status, object types, IDs, counts, and permission booleans;
- performs config check, login/register, org create, invite, accept, confirm, collection create/update, cipher share, sync as both users, unauthorized negative check, and attachment upload/download if credentials are available.

- [ ] **Step 2: Document live verifier inputs**

Update `docs/deployment.md` with the env var names and redaction rule. Do not include real secrets or passwords.

- [ ] **Step 3: Commit verifier**

```bash
git add scripts/live-org-proof.sh docs/deployment.md
git commit -m "test: add live organization proof script"
```

- [ ] **Step 4: Apply live D1 migration**

Use the existing Cloudflare account id:

```bash
set -euo pipefail
set -a
. ../.env.local
set +a
export CLOUDFLARE_API_KEY="${CF_GLOBAL_API_KEY}"
export CLOUDFLARE_EMAIL="${CF_EMAIL}"
export CLOUDFLARE_ACCOUNT_ID="b7f5fb7bd8a4855e8497eac2fe026ab9"
export WRANGLER_LOG_SANITIZE=true
npx wrangler d1 migrations apply vault1 --remote
```

Expected: migration `0014_add_organizations_collections.sql` applied successfully.

- [ ] **Step 5: Deploy Worker**

```bash
npx wrangler deploy
```

Expected: deploy succeeds for `warden-worker` and retains custom domain `secrets.steppingstonesgroup.dev`.

- [ ] **Step 6: Run live proof**

```bash
WARDEN_BASE_URL="https://secrets.steppingstonesgroup.dev" \
WARDEN_PROOF_USER_A_EMAIL="redacted-a@ssg-healthcare.com" \
WARDEN_PROOF_USER_A_PASSWORD="${WARDEN_PROOF_USER_A_PASSWORD}" \
WARDEN_PROOF_USER_B_EMAIL="redacted-b@ssg-healthcare.com" \
WARDEN_PROOF_USER_B_PASSWORD="${WARDEN_PROOF_USER_B_PASSWORD}" \
scripts/live-org-proof.sh
```

Expected:

- `/api/config` reports signup enabled for the SSG domain policy.
- D1 reports the five new tables and indexes.
- User A profile/sync includes the created org.
- User B profile/sync includes the confirmed org after accept/confirm.
- User B sync includes the shared cipher and collection ID.
- Read-only/hide-password tests show `edit=false` and `viewPassword=false` when those permissions are set.
- Non-member access to the shared cipher returns `404`.
- Authorized org attachment upload/download succeeds and unauthorized access fails.

- [ ] **Step 7: Push final branch**

```bash
git push origin codex/security-remediation
```

Expected: all commits are on `The-Stepping-Stones-Group/warden-worker.git` branch `codex/security-remediation`.

## Self-Review Checklist

- Spec coverage: tasks cover schema, model JSON, profile, sync, org/collection routes, member lifecycle, cipher sharing, authorization, attachments, compatibility stubs, docs, deploy, and live proof.
- TDD coverage: each implementation task starts with a failing local test before production code.
- Safety: server stores opaque encrypted values only; live proof redacts tokens, keys, and secret payloads.
- Rollout: D1 migration is applied before deploy proof, and the branch is pushed after local and live verification.
