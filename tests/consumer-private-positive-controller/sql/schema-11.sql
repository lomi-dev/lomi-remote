-- Shared provider throttling is independent of permanent credential circuits.
ALTER TABLE push_project_circuit ADD COLUMN "throttleUntil" TIMESTAMP(3);
