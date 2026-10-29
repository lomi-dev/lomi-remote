-- AlterTable
ALTER TABLE "remote_pairing" ADD COLUMN     "mobileSessionId" TEXT,
ALTER COLUMN "webSessionId" DROP NOT NULL;

-- AlterTable
ALTER TABLE "remote_grant" ADD COLUMN     "mobileSessionId" TEXT,
ALTER COLUMN "webSessionId" DROP NOT NULL;

-- CreateTable
CREATE TABLE "mobile_login" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "redirectUri" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "codeChallenge" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "codeHash" TEXT,
    "codeExpiresAt" TIMESTAMP(3),
    "consumedAt" TIMESTAMP(3),
    "deniedAt" TIMESTAMP(3),
    "userId" TEXT,
    "sourceSessionId" TEXT,

    CONSTRAINT "mobile_login_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mobile_session" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sourceSessionId" TEXT NOT NULL,
    "authorizationId" TEXT NOT NULL,
    "accessHash" TEXT NOT NULL,
    "accessExpiresAt" TIMESTAMP(3) NOT NULL,
    "revocationHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "idleExpiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "mobile_session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mobile_refresh" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "mobile_refresh_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "mobile_login_codeHash_key" ON "mobile_login"("codeHash");

-- CreateIndex
CREATE INDEX "mobile_login_expiresAt_idx" ON "mobile_login"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "mobile_session_accessHash_key" ON "mobile_session"("accessHash");

-- CreateIndex
CREATE UNIQUE INDEX "mobile_session_revocationHash_key" ON "mobile_session"("revocationHash");

-- CreateIndex
CREATE INDEX "mobile_session_expiresAt_idx" ON "mobile_session"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "mobile_refresh_tokenHash_key" ON "mobile_refresh"("tokenHash");

-- CreateIndex
CREATE INDEX "mobile_refresh_sessionId_idx" ON "mobile_refresh"("sessionId");

-- CreateIndex
CREATE INDEX "remote_pairing_mobileSessionId_idx" ON "remote_pairing"("mobileSessionId");

-- CreateIndex
CREATE INDEX "remote_grant_mobileSessionId_idx" ON "remote_grant"("mobileSessionId");

-- AddForeignKey
ALTER TABLE "remote_pairing" ADD CONSTRAINT "remote_pairing_mobileSessionId_fkey" FOREIGN KEY ("mobileSessionId") REFERENCES "mobile_session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remote_grant" ADD CONSTRAINT "remote_grant_mobileSessionId_fkey" FOREIGN KEY ("mobileSessionId") REFERENCES "mobile_session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mobile_login" ADD CONSTRAINT "mobile_login_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mobile_login" ADD CONSTRAINT "mobile_login_sourceSessionId_fkey" FOREIGN KEY ("sourceSessionId") REFERENCES "session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mobile_session" ADD CONSTRAINT "mobile_session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mobile_session" ADD CONSTRAINT "mobile_session_sourceSessionId_fkey" FOREIGN KEY ("sourceSessionId") REFERENCES "session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mobile_session" ADD CONSTRAINT "mobile_session_authorizationId_fkey" FOREIGN KEY ("authorizationId") REFERENCES "remote_service_authorization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mobile_refresh" ADD CONSTRAINT "mobile_refresh_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "mobile_session"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- Existing browser owners remain unchanged. Mobile never masquerades as web.
ALTER TABLE remote_pairing ADD CONSTRAINT remote_pairing_owner_xor CHECK (("webSessionId" IS NULL) <> ("mobileSessionId" IS NULL));
ALTER TABLE remote_grant ADD CONSTRAINT remote_grant_owner_xor CHECK (("webSessionId" IS NULL) <> ("mobileSessionId" IS NULL));

CREATE FUNCTION check_remote_consumer_owner() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE owner_user text; pair remote_pairing%ROWTYPE;
BEGIN
  IF NEW."mobileSessionId" IS NOT NULL THEN
    SELECT "userId" INTO owner_user FROM mobile_session WHERE id = NEW."mobileSessionId";
  ELSE
    SELECT "userId" INTO owner_user FROM remote_web_session WHERE id = NEW."webSessionId";
  END IF;
  IF owner_user IS NULL OR owner_user <> NEW."userId" THEN RAISE EXCEPTION 'Consumer owner mismatch'; END IF;
  IF TG_TABLE_NAME = 'remote_grant' THEN
    SELECT * INTO pair FROM remote_pairing WHERE id = NEW."pairingId";
    IF pair.id IS NULL OR pair."userId" <> NEW."userId" OR pair."hostId" <> NEW."hostId" OR
      pair."deviceId" <> NEW."deviceId" OR pair."webSessionId" IS DISTINCT FROM NEW."webSessionId" OR
      pair."mobileSessionId" IS DISTINCT FROM NEW."mobileSessionId" THEN RAISE EXCEPTION 'Grant pairing owner mismatch'; END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER remote_pairing_owner_guard BEFORE INSERT OR UPDATE ON remote_pairing FOR EACH ROW EXECUTE FUNCTION check_remote_consumer_owner();
CREATE TRIGGER remote_grant_owner_guard BEFORE INSERT OR UPDATE ON remote_grant FOR EACH ROW EXECUTE FUNCTION check_remote_consumer_owner();

CREATE FUNCTION check_mobile_session_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM "session" s JOIN remote_service_authorization a ON a.id = NEW."authorizationId"
   WHERE s.id = NEW."sourceSessionId" AND s."userId" = NEW."userId" AND a."userId" = NEW."userId" AND a."sourceSessionId" = s.id) THEN
   RAISE EXCEPTION 'Mobile parent/authorization owner mismatch';
 END IF;
 IF TG_OP = 'UPDATE' AND (OLD."userId" IS DISTINCT FROM NEW."userId" OR OLD."sourceSessionId" IS DISTINCT FROM NEW."sourceSessionId" OR OLD."authorizationId" IS DISTINCT FROM NEW."authorizationId") THEN
   RAISE EXCEPTION 'Mobile ownership is immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER mobile_session_owner_guard BEFORE INSERT OR UPDATE ON mobile_session FOR EACH ROW EXECUTE FUNCTION check_mobile_session_owner();

CREATE FUNCTION immutable_remote_consumer_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD."userId" IS DISTINCT FROM NEW."userId" OR OLD."webSessionId" IS DISTINCT FROM NEW."webSessionId" OR OLD."mobileSessionId" IS DISTINCT FROM NEW."mobileSessionId" OR OLD."hostId" IS DISTINCT FROM NEW."hostId" OR OLD."deviceId" IS DISTINCT FROM NEW."deviceId" THEN
   RAISE EXCEPTION 'Consumer ownership is immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER remote_pairing_owner_immutable BEFORE UPDATE ON remote_pairing FOR EACH ROW EXECUTE FUNCTION immutable_remote_consumer_owner();
CREATE TRIGGER remote_grant_owner_immutable BEFORE UPDATE ON remote_grant FOR EACH ROW EXECUTE FUNCTION immutable_remote_consumer_owner();
