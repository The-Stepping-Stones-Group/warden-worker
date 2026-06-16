# Organizations and Collections Design

## Context

Warden Worker is currently a personal-vault Bitwarden-compatible backend. The
repo already has a few organization-shaped placeholders, including
`ciphers.organization_id`, attachment organization columns, `Cipher.collectionIds`
serialization, and empty `profile.organizations` / `sync.collections` arrays.
Those placeholders do not make a shared vault work: there are no organization,
membership, collection, collection ACL, cipher-collection join, or organization
route tables, and most cipher access still filters only on `c.user_id`.

Upstream Vaultwarden models shared vaults around confirmed organization
membership and collection access. Ciphers are assigned to organizations and to
collections, users receive an encrypted organization key in their membership
record, and clients learn shared state through profile, sync, collection, member,
and cipher assignment APIs.

## Goal

Implement enough Bitwarden/Vaultwarden-compatible organization and collection
support for `secrets.steppingstonesgroup.dev` so SSG users can create an
organization, invite and confirm members, create collections, share secrets into
collections, sync those shared items from another confirmed account, and reject
non-member or unauthorized access with empirical proof.

## Scope

This design includes:

- Organization records with public/private key metadata.
- Organization memberships with owner/admin/user/manager types, invited,
  accepted, and confirmed statuses, access-all flags, and per-user encrypted
  organization keys.
- Collections and per-user collection permissions.
- Durable cipher-to-collection assignment.
- Profile and sync output for organizations, collections, policies, and org
  ciphers.
- Organization and collection administration routes required by the bundled web
  vault and Bitwarden-compatible clients.
- Org cipher create, share, update, collection assignment, read, delete, restore,
  and attachment access under membership and collection authorization.
- Default no-op or empty responses for client probes around policies, groups,
  billing, events, and enterprise features where needed to keep the web vault
  usable.
- Tests, D1 migration, deploy, and live proof against the Cloudflare Worker.

This design does not include full enterprise group management, SCIM, SSO,
provider organizations, billing enforcement, event/audit reporting, emergency
access, or policy enforcement beyond harmless empty/default compatibility
responses. Clients must see `useGroups: false` until real group support exists.

## Recommended Approach

Build a compatibility-focused organization MVP in one coherent feature branch.
The schema, sync payload, collection ACL, and cipher access rules have to land
together because partial support can create unsafe states where clients believe
an item is organization-owned while the backend still treats it as personal.

Rejected alternatives:

- A "sync-only" fake organization would make the UI appear alive but would not
  provide secure cross-user sharing or permission checks.
- A direct port of all Vaultwarden organization features would be much larger
  than the objective and would introduce unsupported enterprise surfaces before
  the Worker backend has the storage and test coverage for them.

## Data Model

Add these tables to both `sql/schema.sql` and a new migration:

- `organizations`: `id`, `name`, `billing_email`, `private_key`, `public_key`,
  `created_at`, `updated_at`.
- `users_organizations`: `id`, `user_id`, `organization_id`,
  `invited_by_email`, `access_all`, `key`, `status`, `type`,
  `reset_password_key`, `external_id`, `created_at`, `updated_at`.
- `collections`: `id`, `organization_id`, `name`, `external_id`,
  `created_at`, `updated_at`.
- `users_collections`: `user_id`, `collection_id`, `read_only`,
  `hide_passwords`, `manage`, `created_at`, `updated_at`.
- `ciphers_collections`: `cipher_id`, `collection_id`, `created_at`.

Keep existing `ciphers.organization_id` and `attachments.organization_id`.
Backfill is not needed for existing personal rows because `organization_id IS
NULL` remains the personal-vault marker.

Use foreign-key-style indexes even if D1 enforcement is limited:

- Membership by `(user_id, organization_id)`.
- Collections by `organization_id`.
- Collection ACL by `(user_id, collection_id)`.
- Cipher assignments by `(cipher_id, collection_id)` and `collection_id`.
- Org ciphers by `ciphers.organization_id`.

## Authorization Model

Add a shared access helper for cipher operations. It returns a view of a cipher
only when one of these is true:

- The cipher is personal and `ciphers.user_id` matches the authenticated user.
- The cipher belongs to an organization where the user has confirmed
  membership and either:
  - membership has `access_all = true`, or
  - the cipher is assigned to at least one collection where the user has a row in
    `users_collections`.

Permissions are derived from collection ACL and membership type:

- Owners and admins can manage organization ciphers.
- Access-all members can see org ciphers and receive edit/delete permission
  unless the operation is intentionally admin-only.
- Collection users receive `edit = !read_only`,
  `viewPassword = !hide_passwords`, and delete/restore permissions only when
  editable.
- Non-members, unconfirmed members, and members without collection access get
  `404` for item-specific routes to avoid leaking object existence.

Attachment create, upload, download, and delete must use the same access helper.
Org attachments store `organization_id` and continue using the existing R2/KV
storage backend.

## API Surface

Implement these route families:

- `POST /api/organizations`
- `GET /api/organizations/{orgId}`
- `PUT|POST /api/organizations/{orgId}`
- `POST /api/organizations/{orgId}/keys`
- `GET /api/organizations/{orgId}/keys`
- `GET /api/organizations/{orgId}/public-key`
- `GET /api/organizations/{orgId}/collections`
- `GET /api/organizations/{orgId}/collections/details`
- `POST /api/organizations/{orgId}/collections`
- `PUT|POST /api/organizations/{orgId}/collections/{collectionId}`
- `DELETE /api/organizations/{orgId}/collections/{collectionId}`
- `GET /api/collections`
- `GET /api/organizations/{orgId}/users`
- `POST /api/organizations/{orgId}/users/invite`
- `POST /api/organizations/{orgId}/users/{memberId}/accept`
- `POST /api/organizations/{orgId}/users/{memberId}/confirm`
- `POST /api/organizations/{orgId}/users/confirm`
- `GET /api/organizations/{orgId}/users/{memberId}`
- `PUT|POST /api/organizations/{orgId}/users/{memberId}`
- `DELETE /api/organizations/{orgId}/users/{memberId}`
- `POST /api/organizations/{orgId}/users/public-keys`
- `POST|PUT /api/ciphers/{cipherId}/share`
- `POST|PUT /api/ciphers/{cipherId}/collections`
- `POST|PUT /api/ciphers/{cipherId}/collections_v2`

Add empty/default compatibility responses only after observing the bundled web
vault requests them. Expected candidates are policies, groups, billing, events,
and organization tax/payment endpoints.

## Sync and Profile

`/api/accounts/profile` must include `profile.organizations` for confirmed and
accepted memberships with:

- organization id and membership id;
- org name;
- encrypted membership key;
- status and type;
- enabled flags and plan capability flags;
- `hasPublicAndPrivateKeys`;
- `useGroups: false`;
- permissions object with collection management booleans.

`/api/sync` must include:

- `collections` as `collectionDetails` visible to the user;
- `policies` as an empty array for now;
- personal ciphers owned by the user;
- organization ciphers visible through confirmed membership and collection ACL;
- each org cipher's `organizationId`, `collectionIds`, `edit`,
  `viewPassword`, `permissions`, and `organizationUseTotp`.

Existing personal vault sync behavior must remain unchanged.

## Crypto and Trust Boundary

The server stores opaque encrypted values supplied by Bitwarden-compatible
clients. It does not decrypt vault item data, organization keys, user private
keys, or item keys. Invite confirmation stores the encrypted org key for the
target user as supplied by the owner/admin client.

All live verification output must redact auth tokens, encrypted keys, cipher
payloads, and secrets. It may show IDs, email domains, response status codes,
object counts, object types, and boolean permission fields.

## Error Handling

Use existing error response helpers and status-code style:

- `400` for malformed route bodies, invalid collection IDs, or trying to assign
  a cipher to a collection in another organization.
- `401` for missing/invalid auth.
- `403` for authenticated users attempting organization admin operations without
  the right role.
- `404` for ciphers, collections, memberships, or orgs the caller is not allowed
  to know exist.
- `409` for duplicate invite/membership cases where the client can recover.

Mutating routes must update revision date behavior consistently with existing
cipher/folder flows so clients know to resync.

## Testing Strategy

Follow test-first implementation. Add focused tests before production code for:

- migration/schema creation of organization and collection tables;
- profile organization serialization;
- sync collection serialization;
- sync includes org ciphers visible through collection ACL;
- sync excludes org ciphers from unconfirmed or non-member users;
- create/share persists `ciphers_collections`;
- read-only collection users cannot update/delete org ciphers;
- hide-password collection users receive `viewPassword=false`;
- owners/admins can create collections and confirm members;
- org attachments use shared cipher authorization;
- personal vault behavior still works.

Existing `cargo test --locked` and `cargo fmt -- --check` must pass before
deployment.

## Live Verification Contract

After deploy to Cloudflare:

1. Confirm D1 has the new tables and indexes.
2. Confirm `/api/config` still has signups enabled for `*@ssg-healthcare.com`.
3. Register or use two test users in the `ssg-healthcare.com` domain.
4. User A creates an organization and initial collection.
5. User A invites User B.
6. User B accepts; User A confirms with User B's encrypted org key.
7. User A creates or shares a cipher into the collection.
8. User B syncs and sees the organization, collection, and shared cipher.
9. User B updates/deletes only when granted editable permission.
10. A non-member or wrong-domain account cannot read the org cipher.
11. Org attachment upload/download works for an authorized member and fails for
    an unauthorized account.
12. Capture redacted evidence: endpoint, status, object type/count, org id,
    collection id, `collectionIds`, `edit`, `viewPassword`, and negative-test
    status codes.

Where the bundled web vault or browser extension can be driven reliably, verify
the same flow through the client UI. If client automation is unstable, direct API
proof is acceptable only when it exercises the same routes and sync surfaces.

## Rollout and Safety

Deploy in this order:

1. Commit spec and implementation plan.
2. Add tests and implementation in small commits.
3. Run local tests and format checks.
4. Apply D1 migration to the live database.
5. Deploy Worker to the existing `warden-worker`.
6. Run live proof before announcing completion.

Do not mark the goal complete unless current evidence proves the schema, API,
authorization, sync behavior, deployment, and live shared-vault verification are
all satisfied.
