-- Control-plane identity, workspace, project, and device tables (plan §28).
-- Structural milestone: validated by tests for table coverage only; no
-- live database is exercised in this phase.

BEGIN;

CREATE TABLE users (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login               TEXT NOT NULL UNIQUE,
    display_name        TEXT,
    credential_verifier TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workspaces (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id  TEXT NOT NULL UNIQUE CHECK (workspace_id LIKE 'ws\_%'),
    name          TEXT NOT NULL,
    owner_user_id BIGINT NOT NULL REFERENCES users (id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workspace_members (
    workspace_id BIGINT NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    user_id      BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role         TEXT NOT NULL DEFAULT 'member'
                 CHECK (role IN ('owner', 'member', 'viewer')),
    PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE projects (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id   TEXT NOT NULL UNIQUE CHECK (project_id LIKE 'proj\_%'),
    workspace_id BIGINT NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    public_key    BYTEA NOT NULL UNIQUE,
    label         TEXT,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE project_members (
    project_id BIGINT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    user_id    BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'member'
               CHECK (role IN ('owner', 'member', 'viewer')),
    PRIMARY KEY (project_id, user_id)
);

COMMIT;
