-- Additive E2 foundation: no legacy UUID assumptions or account-status mirror.
ALTER TABLE "session" ADD CONSTRAINT "session_id_userId_key" UNIQUE (id, "userId");
CREATE TABLE remote_account_identity (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 "userId" text NOT NULL UNIQUE REFERENCES "user"(id) ON DELETE CASCADE ON UPDATE NO ACTION,
 "authorizationEpoch" bigint NOT NULL DEFAULT 1 CHECK ("authorizationEpoch">=1),
 UNIQUE(id,"userId")
);
CREATE TABLE remote_session_binding (
 "sessionId" text PRIMARY KEY, "userId" text NOT NULL, "accountId" uuid NOT NULL,
 "clientClass" text NOT NULL CHECK ("clientClass" IN ('web','mobile','desktop','bootstrap')),
 FOREIGN KEY("sessionId","userId") REFERENCES "session"(id,"userId") ON DELETE CASCADE ON UPDATE NO ACTION,
 FOREIGN KEY("accountId","userId") REFERENCES remote_account_identity(id,"userId") ON DELETE CASCADE ON UPDATE NO ACTION,
 UNIQUE("sessionId","accountId","clientClass"),
 UNIQUE("sessionId","userId")
);
CREATE TABLE host_enrollment (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), "hostId" uuid NOT NULL,
 "signedHostKey" jsonb NOT NULL CHECK (jsonb_typeof("signedHostKey")='object'),
 "initialCommitment" bytea NOT NULL CHECK (octet_length("initialCommitment")=32),
 "deviceCodeHash" bytea NOT NULL UNIQUE CHECK (octet_length("deviceCodeHash")=32),
 "bootstrapId" uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 "exchangeOperationId" uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 nonce bytea NOT NULL CHECK (octet_length(nonce)=32),
 "clientClass" text NOT NULL DEFAULT 'host' CHECK ("clientClass"='host'),
 "expiresAt" timestamptz(3) NOT NULL,
 "accountId" uuid REFERENCES remote_account_identity(id) ON DELETE CASCADE ON UPDATE NO ACTION,
 "approvedEpoch" bigint CHECK ("approvedEpoch">=1),
 "hostKeyFingerprint" bytea CHECK (octet_length("hostKeyFingerprint")=32),
 approved boolean NOT NULL DEFAULT false, consumed boolean NOT NULL DEFAULT false,
 revoked boolean NOT NULL DEFAULT false,
 CHECK ((approved AND "accountId" IS NOT NULL AND "approvedEpoch" IS NOT NULL AND "hostKeyFingerprint" IS NOT NULL)
     OR (NOT approved AND "accountId" IS NULL AND "approvedEpoch" IS NULL AND "hostKeyFingerprint" IS NULL)),
 CHECK (NOT consumed OR approved),
 UNIQUE(id,"accountId","bootstrapId")
);
CREATE INDEX "host_enrollment_expiresAt_idx" ON host_enrollment("expiresAt");
-- No deviceCode FK: Better Auth consumeOne must delete its device code normally.
-- No approval-browser-session FK: independent host authorization must outlive it.
CREATE TABLE host_bootstrap (
 id uuid PRIMARY KEY, "enrollmentId" uuid NOT NULL UNIQUE, "accountId" uuid NOT NULL,
 "sessionId" text NOT NULL UNIQUE,
 "clientClass" text NOT NULL DEFAULT 'bootstrap' CHECK ("clientClass"='bootstrap'),
 consumed boolean NOT NULL DEFAULT false, revoked boolean NOT NULL DEFAULT false,
 FOREIGN KEY("enrollmentId","accountId",id) REFERENCES host_enrollment(id,"accountId","bootstrapId") ON DELETE CASCADE ON UPDATE NO ACTION,
 FOREIGN KEY("sessionId","accountId","clientClass") REFERENCES remote_session_binding("sessionId","accountId","clientClass") ON DELETE CASCADE ON UPDATE NO ACTION
);
ALTER TABLE host_bootstrap ADD UNIQUE("enrollmentId","accountId",id), ADD UNIQUE("sessionId","accountId","clientClass");
CREATE FUNCTION lomi_remote_identity_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
   IF NEW."authorizationEpoch"<>1 THEN RAISE EXCEPTION 'initial epoch must be one' USING ERRCODE='23514'; END IF;
 ELSIF (NEW.id,NEW."userId") IS DISTINCT FROM (OLD.id,OLD."userId") OR NEW."authorizationEpoch"<OLD."authorizationEpoch" THEN
   RAISE EXCEPTION 'immutable remote identity or epoch rollback' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER remote_identity_guard BEFORE INSERT OR UPDATE ON remote_account_identity FOR EACH ROW EXECUTE FUNCTION lomi_remote_identity_guard();
CREATE FUNCTION lomi_remote_session_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
 IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'immutable server session binding' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER remote_session_guard BEFORE UPDATE ON remote_session_binding FOR EACH ROW EXECUTE FUNCTION lomi_remote_session_guard();
CREATE FUNCTION lomi_host_enrollment_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE epoch bigint; account_status text;
BEGIN
 IF TG_OP='INSERT' THEN
   IF NEW.approved OR NEW.consumed OR NEW.revoked THEN RAISE EXCEPTION 'enrollment must start pending' USING ERRCODE='23514'; END IF;
 ELSE
   IF (NEW.id,NEW."hostId",NEW."signedHostKey",NEW."initialCommitment",NEW."deviceCodeHash",NEW."bootstrapId",NEW."exchangeOperationId",NEW.nonce,NEW."clientClass",NEW."expiresAt")
      IS DISTINCT FROM (OLD.id,OLD."hostId",OLD."signedHostKey",OLD."initialCommitment",OLD."deviceCodeHash",OLD."bootstrapId",OLD."exchangeOperationId",OLD.nonce,OLD."clientClass",OLD."expiresAt")
      OR (OLD.approved AND (NEW."accountId",NEW."approvedEpoch",NEW."hostKeyFingerprint",NEW.approved) IS DISTINCT FROM (OLD."accountId",OLD."approvedEpoch",OLD."hostKeyFingerprint",OLD.approved))
      OR (OLD.consumed AND NOT NEW.consumed) OR (OLD.revoked AND NEW IS DISTINCT FROM OLD)
   THEN RAISE EXCEPTION 'immutable enrollment or terminal transition' USING ERRCODE='23514'; END IF;
 END IF;
 -- Revocation remains possible after expiry/epoch changes. Approval and consume
 -- serialize against epoch updates and real User.status changes.
 IF (TG_OP='UPDATE' AND ((NEW.approved AND NOT OLD.approved) OR (NEW.consumed AND NOT OLD.consumed))) THEN
   SELECT u.status INTO account_status FROM public."user" u JOIN public.remote_account_identity a ON a."userId"=u.id WHERE a.id=NEW."accountId" FOR SHARE OF u;
   SELECT "authorizationEpoch" INTO epoch FROM public.remote_account_identity WHERE id=NEW."accountId" FOR SHARE;
   IF OLD.revoked OR NEW.revoked OR NEW."expiresAt"<=clock_timestamp() OR account_status IS DISTINCT FROM 'active' OR epoch IS DISTINCT FROM NEW."approvedEpoch" THEN
     RAISE EXCEPTION 'expired, inactive, revoked or stale enrollment' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER host_enrollment_guard BEFORE INSERT OR UPDATE ON host_enrollment FOR EACH ROW EXECUTE FUNCTION lomi_host_enrollment_guard();
CREATE FUNCTION lomi_host_bootstrap_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE e public.host_enrollment; session_expiry timestamptz; epoch bigint; account_status text;
BEGIN
 IF TG_OP='DELETE' THEN
   -- Keep a tombstone: deleting/expiring a bootstrap never allows remapping it.
   UPDATE public.host_enrollment SET revoked=true WHERE id=OLD."enrollmentId" AND NOT revoked AND NOT consumed AND "expiresAt">clock_timestamp();
   RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' THEN
   IF (NEW.id,NEW."enrollmentId",NEW."accountId",NEW."sessionId",NEW."clientClass") IS DISTINCT FROM (OLD.id,OLD."enrollmentId",OLD."accountId",OLD."sessionId",OLD."clientClass")
      OR (OLD.consumed AND NOT NEW.consumed) OR (OLD.revoked AND NEW IS DISTINCT FROM OLD) THEN
     RAISE EXCEPTION 'immutable bootstrap or terminal transition' USING ERRCODE='23514';
   END IF;
 END IF;
 IF TG_OP='INSERT' OR (NEW.consumed AND NOT OLD.consumed) THEN
   SELECT u.status INTO account_status FROM public."user" u JOIN public.remote_account_identity a ON a."userId"=u.id WHERE a.id=NEW."accountId" FOR SHARE OF u;
   SELECT "authorizationEpoch" INTO epoch FROM public.remote_account_identity WHERE id=NEW."accountId" FOR SHARE;
   SELECT * INTO e FROM public.host_enrollment WHERE id=NEW."enrollmentId" FOR UPDATE;
   -- Legacy Better Auth/Prisma session timestamps contain UTC dates. Explicit
   -- interpretation prevents caller TimeZone from changing session authority.
   SELECT "expiresAt" AT TIME ZONE 'UTC' INTO session_expiry FROM public."session" WHERE id=NEW."sessionId" FOR SHARE;
   IF NOT FOUND OR session_expiry<=clock_timestamp() OR NOT e.approved OR e.revoked OR e.consumed OR NEW.revoked OR e."expiresAt"<=clock_timestamp() OR account_status IS DISTINCT FROM 'active' OR epoch IS DISTINCT FROM e."approvedEpoch" OR (TG_OP='INSERT' AND NEW.consumed) THEN
     RAISE EXCEPTION 'bootstrap requires live approved enrollment and session' USING ERRCODE='23514';
   END IF;
 END IF;
 IF TG_OP='UPDATE' AND NEW.consumed AND NOT OLD.consumed THEN
   UPDATE public.host_enrollment SET consumed=true WHERE id=NEW."enrollmentId";
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER host_bootstrap_guard BEFORE INSERT OR UPDATE OR DELETE ON host_bootstrap FOR EACH ROW EXECUTE FUNCTION lomi_host_bootstrap_guard();
REVOKE ALL ON FUNCTION lomi_remote_identity_guard(),lomi_remote_session_guard(),lomi_host_enrollment_guard(),lomi_host_bootstrap_guard() FROM PUBLIC;
