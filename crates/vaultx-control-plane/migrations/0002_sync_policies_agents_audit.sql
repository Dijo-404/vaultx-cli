-- Control-plane sync, policy, agent, audit, and cursor tables (plan §28).
-- Encrypted object payloads may live in object storage; the envelope
-- metadata and content hashes recorded here stay in PostgreSQL.

BEGIN;

CREATE TABLE objects (
    project_id   BIGINT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    object_id    TEXT NOT NULL CHECK (object_id LIKE 'obj\_%'),
    content_hash TEXT NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    size_bytes   BIGINT NOT NULL,
    envelope     JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, object_id)
);

CREATE TABLE refs (
    project_id BIGINT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    namespace  TEXT NOT NULL CHECK (namespace IN ('heads', 'environments')),
    name       TEXT NOT NULL,
    commit_id  TEXT NOT NULL CHECK (commit_id LIKE 'cmt\_%'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, namespace, name)
);

CREATE TABLE environments (
    project_id BIGINT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    protected  BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (project_id, name)
);

CREATE TABLE policies (
    project_id BIGINT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    document   JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, name)
);

CREATE TABLE policy_bindings (
    project_id   BIGINT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('agent', 'role', 'user')),
    subject_id   TEXT NOT NULL,
    policy_name  TEXT NOT NULL,
    PRIMARY KEY (project_id, subject_type, subject_id, policy_name),
    FOREIGN KEY (project_id, policy_name)
        REFERENCES policies (project_id, name) ON DELETE CASCADE
);

CREATE TABLE agent_identities (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agent_id     TEXT NOT NULL UNIQUE CHECK (agent_id LIKE 'agent\_%'),
    project_id   BIGINT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    created_by   BIGINT NOT NULL REFERENCES users (id),
    revoked      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE agent_sessions (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id        TEXT NOT NULL UNIQUE CHECK (session_id LIKE 'sess\_%'),
    agent_identity_id BIGINT NOT NULL
                      REFERENCES agent_identities (id) ON DELETE CASCADE,
    parent_principal  TEXT NOT NULL,
    token_verifier    TEXT NOT NULL UNIQUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ
);

CREATE TABLE audit_events (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id    TEXT NOT NULL UNIQUE CHECK (event_id LIKE 'aud\_%'),
    project_id  BIGINT REFERENCES projects (id) ON DELETE SET NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sync_state (
    project_id        BIGINT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    device_public_key BYTEA NOT NULL REFERENCES devices (public_key),
    last_commit_id    TEXT,
    last_synced_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, device_public_key)
);

COMMIT;
