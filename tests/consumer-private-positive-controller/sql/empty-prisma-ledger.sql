-- Empty fixture-only compatibility table for the frozen permissions REVOKE.
-- Source: https://github.com/prisma/prisma-engines/blob/main/schema-engine/ARCHITECTURE.md
-- No Prisma engine execution, migration history, rows or applied claims.
CREATE TABLE public._prisma_migrations (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    finished_at TIMESTAMPTZ,
    migration_name VARCHAR(255) NOT NULL,
    logs TEXT,
    rolled_back_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_steps_count INTEGER NOT NULL DEFAULT 0
);
SELECT count(*) FROM public._prisma_migrations;
