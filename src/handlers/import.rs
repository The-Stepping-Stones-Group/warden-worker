use axum::{extract::State, Json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;
use worker::{D1PreparedStatement, Env};

use crate::d1_query;

use crate::auth::Claims;
use crate::db::{self, touch_user_updated_at};
use crate::error::AppError;
use crate::models::cipher::{Cipher, CipherData};
use crate::models::folder::Folder;
use crate::models::import::ImportRequest;
use crate::notifications::{self, UpdateType};

use super::{
    ciphers::{
        normalize_collection_ids, replace_cipher_collections, touch_cipher_scope_updated_at,
        validate_cipher_org_assignment,
    },
    get_batch_size,
};

/// Import ciphers and folders.
/// Aligned with vaultwarden's POST /ciphers/import implementation.
#[worker::send]
pub async fn import_data(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(data): Json<ImportRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();
    let batch_size = get_batch_size(&env);

    // Get existing folders for this user
    let existing_folder_rows = d1_query!(
        &db,
        "SELECT id FROM folders WHERE user_id = ?1",
        &claims.sub
    )
    .map_err(|_| AppError::Database)?
    .all()
    .await?
    .results::<FolderIdRow>()?;

    let existing_folders: HashSet<String> =
        existing_folder_rows.into_iter().map(|row| row.id).collect();

    // Process folders and build the folder_id list
    let mut folder_statements: Vec<D1PreparedStatement> = Vec::new();
    let mut folders: Vec<String> = Vec::with_capacity(data.folders.len());

    for import_folder in data.folders {
        let folder_id = if let Some(ref id) = import_folder.id {
            if existing_folders.contains(id) {
                // Folder already exists, use existing ID
                id.clone()
            } else {
                // Folder doesn't exist, create new one with provided ID
                let folder = Folder {
                    id: id.clone(),
                    user_id: claims.sub.clone(),
                    name: import_folder.name.clone(),
                    created_at: now.clone(),
                    updated_at: now.clone(),
                };

                let stmt = d1_query!(
                    &db,
                    "INSERT INTO folders (id, user_id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    folder.id,
                    folder.user_id,
                    folder.name,
                    folder.created_at,
                    folder.updated_at
                )
                .map_err(|_| AppError::Database)?;

                folder_statements.push(stmt);
                id.clone()
            }
        } else {
            // No ID provided, create new folder with generated UUID
            let new_id = Uuid::new_v4().to_string();
            let folder = Folder {
                id: new_id.clone(),
                user_id: claims.sub.clone(),
                name: import_folder.name.clone(),
                created_at: now.clone(),
                updated_at: now.clone(),
            };

            let stmt = d1_query!(
                &db,
                "INSERT INTO folders (id, user_id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                folder.id,
                folder.user_id,
                folder.name,
                folder.created_at,
                folder.updated_at
            )
            .map_err(|_| AppError::Database)?;

            folder_statements.push(stmt);
            new_id
        };

        folders.push(folder_id);
    }

    // Execute folder inserts in batches
    if !folder_statements.is_empty() {
        db::execute_in_batches(&db, folder_statements, batch_size).await?;
    }

    // Build the relations map: cipher_index -> folder_index
    // Each cipher can only be in one folder at a time
    let mut relations_map: HashMap<usize, usize> =
        HashMap::with_capacity(data.folder_relationships.len());
    for relation in data.folder_relationships {
        relations_map.insert(relation.key, relation.value);
    }

    // Prepare all cipher insert statements
    let mut cipher_statements: Vec<D1PreparedStatement> = Vec::with_capacity(data.ciphers.len());
    let mut cipher_collection_updates: Vec<(String, Vec<String>)> = Vec::new();
    let mut touched_org_ids: HashSet<String> = HashSet::new();

    for (index, import_cipher) in data.ciphers.into_iter().enumerate() {
        // Determine folder_id from folder_relationships
        let folder_id = relations_map
            .get(&index)
            .and_then(|folder_idx| folders.get(*folder_idx).cloned());
        let organization_id = import_cipher.organization_id.clone();
        let collection_ids =
            normalize_collection_ids(import_cipher.collection_ids.clone().unwrap_or_default());
        if organization_id.is_some() && folder_id.is_some() {
            return Err(AppError::BadRequest(
                "Organization ciphers cannot be assigned to a personal folder".to_string(),
            ));
        }
        validate_cipher_org_assignment(
            &db,
            &claims.sub,
            organization_id.as_deref(),
            &collection_ids,
        )
        .await?;

        let cipher_data = CipherData::new(
            import_cipher.name,
            import_cipher.notes,
            import_cipher.type_fields,
        );

        let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;
        let cipher_id = Uuid::new_v4().to_string();

        let cipher = Cipher {
            id: cipher_id.clone(),
            user_id: Some(claims.sub.clone()),
            organization_id,
            r#type: import_cipher.r#type,
            data: data_value,
            favorite: import_cipher.favorite.unwrap_or(false),
            folder_id,
            deleted_at: None,
            archived_at: None,
            created_at: now.clone(),
            updated_at: now.clone(),
            object: "cipher".to_string(),
            organization_use_totp: false,
            edit: true,
            view_password: true,
            collection_ids: None,
            attachments: None,
        };

        let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

        let stmt = d1_query!(
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
        ).map_err(|_| AppError::Database)?;

        cipher_statements.push(stmt);
        if let Some(org_id) = cipher.organization_id.as_ref() {
            touched_org_ids.insert(org_id.clone());
        }
        cipher_collection_updates.push((cipher_id, collection_ids));
    }

    // Execute cipher inserts in batches
    if !cipher_statements.is_empty() {
        db::execute_in_batches(&db, cipher_statements, batch_size).await?;
    }

    for (cipher_id, collection_ids) in cipher_collection_updates {
        replace_cipher_collections(&db, &cipher_id, &collection_ids, &now).await?;
    }

    touch_user_updated_at(&db, &claims.sub, &now).await?;
    for org_id in touched_org_ids {
        touch_cipher_scope_updated_at(&db, &claims.sub, Some(&org_id), &now).await?;
    }

    notifications::publish_user_update(
        (*env).clone(),
        claims.sub,
        UpdateType::SyncVault,
        now,
        Some(claims.device),
    );

    Ok(Json(()))
}

/// Helper struct for querying existing folder IDs
#[derive(serde::Deserialize)]
struct FolderIdRow {
    id: String,
}
