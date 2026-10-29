-- DropIndex
DROP INDEX "session_userId_idx";

-- CreateIndex
CREATE INDEX "deviceCode_userId_idx" ON "deviceCode"("userId");

-- CreateIndex
CREATE INDEX "deviceCode_expiresAt_idx" ON "deviceCode"("expiresAt");

-- CreateIndex
CREATE INDEX "rateLimit_lastRequest_idx" ON "rateLimit"("lastRequest");

-- CreateIndex
CREATE INDEX "session_expiresAt_idx" ON "session"("expiresAt");

-- CreateIndex
CREATE INDEX "session_userId_createdAt_id_idx" ON "session"("userId", "createdAt", "id");

-- CreateIndex
CREATE INDEX "verification_expiresAt_idx" ON "verification"("expiresAt");

-- Serialize session creation and expiry renewal with changes to the owning user's status.
-- The lock is intentionally per user and does not hold the device-flow global lock over OAuth HTTP.
CREATE FUNCTION "lomi_require_active_session_user"() RETURNS TRIGGER AS $$
DECLARE
    current_status TEXT;
BEGIN
    SELECT "status" INTO current_status
      FROM "user"
      WHERE "id" = NEW."userId"
      FOR UPDATE;

    IF current_status IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'session user is not active'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "session_active_user_guard"
    BEFORE INSERT OR UPDATE OF "expiresAt" ON "session"
    FOR EACH ROW
    EXECUTE FUNCTION "lomi_require_active_session_user"();
