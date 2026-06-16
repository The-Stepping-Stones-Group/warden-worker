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
