-- Database foundation only. Canonical key/proof verification, credential TTLs,
-- receipt encryption and atomic exchange/rotation coordinators are future work.
CREATE TABLE host_identity (
 "hostId" uuid PRIMARY KEY,
 "accountId" uuid NOT NULL REFERENCES public.remote_account_identity(id) ON DELETE CASCADE ON UPDATE NO ACTION,
 "firstEnrollmentId" uuid NOT NULL UNIQUE REFERENCES public.host_enrollment(id) ON DELETE NO ACTION ON UPDATE NO ACTION DEFERRABLE INITIALLY DEFERRED,
 "signedHostKey" jsonb NOT NULL CHECK (jsonb_typeof("signedHostKey")='object'),
 "initialCommitment" bytea NOT NULL CHECK (octet_length("initialCommitment")=32),
 "hostKeyFingerprint" bytea NOT NULL CHECK (octet_length("hostKeyFingerprint")=32),
 "accessEpoch" bigint NOT NULL DEFAULT 1 CHECK ("accessEpoch">=1),
 UNIQUE("hostId","accountId")
);
CREATE TABLE host_authorization (
 id uuid PRIMARY KEY,
 "enrollmentId" uuid NOT NULL UNIQUE REFERENCES public.host_enrollment(id) ON DELETE NO ACTION ON UPDATE NO ACTION DEFERRABLE INITIALLY DEFERRED,
 "hostId" uuid NOT NULL, "accountId" uuid NOT NULL REFERENCES public.remote_account_identity(id) ON DELETE CASCADE ON UPDATE NO ACTION,
 "approvedAccountEpoch" bigint NOT NULL CHECK ("approvedAccountEpoch">=1),
 "hostAccessEpoch" bigint NOT NULL CHECK ("hostAccessEpoch">=1),
 "clientClass" text NOT NULL DEFAULT 'host' CHECK ("clientClass"='host'),
 revoked boolean NOT NULL DEFAULT false, confirmed boolean NOT NULL DEFAULT false,
 rotation bigint NOT NULL DEFAULT 0 CHECK (rotation>=0),
 "accessHash" bytea NOT NULL UNIQUE CHECK (octet_length("accessHash")=32),
 "accessExpiresAt" timestamptz(3) NOT NULL, "idleExpiresAt" timestamptz(3) NOT NULL,
 "createdAt" timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY("hostId","accountId") REFERENCES public.host_identity("hostId","accountId") ON DELETE CASCADE ON UPDATE NO ACTION
);
CREATE UNIQUE INDEX host_authorization_active_host_key ON host_authorization("hostId") WHERE NOT revoked;
CREATE TABLE host_refresh_credential (
 "tokenHash" bytea PRIMARY KEY CHECK (octet_length("tokenHash")=32),
 "authorizationId" uuid NOT NULL REFERENCES public.host_authorization(id) ON DELETE CASCADE ON UPDATE NO ACTION,
 rotation bigint NOT NULL CHECK (rotation>=0), "consumedOperationId" uuid,
 "expiresAt" timestamptz(3) NOT NULL,
 UNIQUE("authorizationId",rotation), UNIQUE("authorizationId","tokenHash")
);
CREATE TABLE host_credential_recovery (
 "authorizationId" uuid NOT NULL REFERENCES public.host_authorization(id) ON DELETE CASCADE ON UPDATE NO ACTION,
 kind text NOT NULL CHECK (kind IN ('exchange','rotate')), "operationId" uuid NOT NULL,
 "requestHash" bytea NOT NULL CHECK (octet_length("requestHash")=32),
 "priorCredentialHash" bytea CHECK (octet_length("priorCredentialHash")=32),
 "sealedResponse" bytea CHECK (octet_length("sealedResponse") BETWEEN 1 AND 16384),
 "expiresAt" timestamptz(3) NOT NULL, "createdAt" timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY("authorizationId",kind,"operationId"), UNIQUE("authorizationId",kind),
 CHECK ((kind='exchange' AND "priorCredentialHash" IS NULL) OR (kind='rotate' AND "priorCredentialHash" IS NOT NULL)),
 FOREIGN KEY("authorizationId","priorCredentialHash") REFERENCES public.host_refresh_credential("authorizationId","tokenHash") ON DELETE CASCADE ON UPDATE NO ACTION
);
CREATE FUNCTION lomi_host_identity_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE e public.host_enrollment; b public.host_bootstrap; epoch bigint; account_status text; session_expiry timestamptz;
BEGIN
 IF TG_OP='UPDATE' THEN
   IF (NEW."hostId",NEW."accountId",NEW."firstEnrollmentId",NEW."signedHostKey",NEW."initialCommitment",NEW."hostKeyFingerprint") IS DISTINCT FROM
      (OLD."hostId",OLD."accountId",OLD."firstEnrollmentId",OLD."signedHostKey",OLD."initialCommitment",OLD."hostKeyFingerprint") OR
      (NEW."accessEpoch"<>OLD."accessEpoch" AND NEW."accessEpoch"<>OLD."accessEpoch"+1) THEN
     RAISE EXCEPTION 'immutable host identity or invalid epoch advance' USING ERRCODE='23514';
   END IF;
   IF NEW."accessEpoch"<>OLD."accessEpoch" AND EXISTS (SELECT FROM public.host_authorization WHERE "hostId"=OLD."hostId" AND NOT revoked) THEN
     RAISE EXCEPTION 'revoke active family before advancing host epoch' USING ERRCODE='23514';
   END IF;
 ELSE
   SELECT * INTO e FROM public.host_enrollment WHERE id=NEW."firstEnrollmentId" FOR UPDATE;
   IF NOT FOUND OR NOT e.approved OR e.revoked OR e.consumed OR e."expiresAt"<=clock_timestamp() OR NEW."accessEpoch"<>1 OR
      (NEW."hostId",NEW."accountId",NEW."signedHostKey",NEW."initialCommitment",NEW."hostKeyFingerprint") IS DISTINCT FROM
      (e."hostId",e."accountId",e."signedHostKey",e."initialCommitment",e."hostKeyFingerprint") THEN
     RAISE EXCEPTION 'host identity requires exact approved enrollment' USING ERRCODE='23514';
   END IF;
   SELECT u.status INTO account_status FROM public."user" u JOIN public.remote_account_identity a ON a."userId"=u.id WHERE a.id=NEW."accountId" FOR SHARE OF u;
   SELECT "authorizationEpoch" INTO epoch FROM public.remote_account_identity WHERE id=NEW."accountId" FOR SHARE;
   SELECT * INTO b FROM public.host_bootstrap WHERE id=e."bootstrapId" AND "enrollmentId"=e.id AND "accountId"=e."accountId" FOR UPDATE;
   IF NOT FOUND OR b.consumed OR b.revoked OR account_status IS DISTINCT FROM 'active' OR epoch IS DISTINCT FROM e."approvedEpoch" THEN
     RAISE EXCEPTION 'identity requires current live bootstrap and account' USING ERRCODE='23514';
   END IF;
   SELECT "expiresAt" AT TIME ZONE 'UTC' INTO session_expiry FROM public."session" WHERE id=b."sessionId" FOR SHARE;
   IF NOT FOUND OR session_expiry<=clock_timestamp() THEN RAISE EXCEPTION 'identity bootstrap session expired' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER host_identity_guard BEFORE INSERT OR UPDATE ON host_identity FOR EACH ROW EXECUTE FUNCTION lomi_host_identity_guard();
CREATE FUNCTION lomi_host_authorization_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE e public.host_enrollment; h public.host_identity; b public.host_bootstrap; epoch bigint; account_status text; session_expiry timestamptz; prior_epoch bigint;
BEGIN
 IF TG_OP='UPDATE' THEN
   IF (NEW.id,NEW."enrollmentId",NEW."hostId",NEW."accountId",NEW."approvedAccountEpoch",NEW."hostAccessEpoch",NEW."clientClass",NEW."createdAt") IS DISTINCT FROM
      (OLD.id,OLD."enrollmentId",OLD."hostId",OLD."accountId",OLD."approvedAccountEpoch",OLD."hostAccessEpoch",OLD."clientClass",OLD."createdAt") OR
      (OLD.revoked AND NEW IS DISTINCT FROM OLD) OR (OLD.confirmed AND NOT NEW.confirmed) OR
      (NEW.rotation<>OLD.rotation AND NEW.rotation<>OLD.rotation+1) OR
      (NEW.rotation=OLD.rotation AND (NEW."accessHash",NEW."accessExpiresAt",NEW."idleExpiresAt") IS DISTINCT FROM (OLD."accessHash",OLD."accessExpiresAt",OLD."idleExpiresAt")) THEN
     RAISE EXCEPTION 'immutable family or invalid transition' USING ERRCODE='23514';
   END IF;
   -- Revoke must remain available even after suspension, expiry or epoch fencing.
   IF NEW.rotation=OLD.rotation THEN RETURN NEW; END IF;
   IF NEW.revoked OR NOT EXISTS (SELECT FROM public.host_refresh_credential WHERE "authorizationId"=OLD.id AND rotation=OLD.rotation AND "consumedOperationId" IS NOT NULL) THEN
     RAISE EXCEPTION 'rotation requires consumed current credential' USING ERRCODE='23514';
   END IF;
 ELSE
   IF NEW.rotation<>0 OR NEW.confirmed OR NEW.revoked THEN RAISE EXCEPTION 'family must start unconfirmed at rotation zero' USING ERRCODE='23514'; END IF;
 END IF;
 SELECT u.status INTO account_status FROM public."user" u JOIN public.remote_account_identity a ON a."userId"=u.id WHERE a.id=NEW."accountId" FOR SHARE OF u;
 SELECT "authorizationEpoch" INTO epoch FROM public.remote_account_identity WHERE id=NEW."accountId" FOR SHARE;
 SELECT * INTO h FROM public.host_identity WHERE "hostId"=NEW."hostId" FOR UPDATE;
 IF NOT FOUND OR account_status IS DISTINCT FROM 'active' OR epoch IS DISTINCT FROM NEW."approvedAccountEpoch" OR
    (NEW."accountId",NEW."hostAccessEpoch") IS DISTINCT FROM (h."accountId",h."accessEpoch") OR NEW."accessExpiresAt"<=clock_timestamp() OR NEW."idleExpiresAt"<=clock_timestamp() OR
    (TG_OP='UPDATE' AND OLD."idleExpiresAt"<=clock_timestamp()) THEN
   RAISE EXCEPTION 'family requires live account and host epochs' USING ERRCODE='23514';
 END IF;
 IF TG_OP='INSERT' THEN
   SELECT * INTO e FROM public.host_enrollment WHERE id=NEW."enrollmentId" FOR UPDATE;
   IF NOT FOUND OR NOT e.approved OR e.revoked OR e.consumed OR e."expiresAt"<=clock_timestamp() OR
      (NEW."hostId",NEW."accountId",NEW."approvedAccountEpoch",h."signedHostKey",h."initialCommitment",h."hostKeyFingerprint") IS DISTINCT FROM
      (e."hostId",e."accountId",e."approvedEpoch",e."signedHostKey",e."initialCommitment",e."hostKeyFingerprint") THEN
     RAISE EXCEPTION 'family requires exact live approved enrollment' USING ERRCODE='23514';
   END IF;
   SELECT * INTO b FROM public.host_bootstrap WHERE id=e."bootstrapId" AND "enrollmentId"=e.id AND "accountId"=e."accountId" FOR UPDATE;
   IF NOT FOUND OR b.consumed OR b.revoked THEN RAISE EXCEPTION 'family requires exact live bootstrap' USING ERRCODE='23514'; END IF;
   SELECT "expiresAt" AT TIME ZONE 'UTC' INTO session_expiry FROM public."session" WHERE id=b."sessionId" FOR SHARE;
   IF NOT FOUND OR session_expiry<=clock_timestamp() THEN RAISE EXCEPTION 'bootstrap session expired' USING ERRCODE='23514'; END IF;
   SELECT max("hostAccessEpoch") INTO prior_epoch FROM public.host_authorization WHERE "hostId"=NEW."hostId";
   IF (prior_epoch IS NULL AND (NEW."hostAccessEpoch"<>1 OR NEW."enrollmentId"<>h."firstEnrollmentId")) OR
      (prior_epoch IS NOT NULL AND NEW."hostAccessEpoch"<=prior_epoch) THEN
     RAISE EXCEPTION 'new family requires next host epoch' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER host_authorization_guard BEFORE INSERT OR UPDATE ON host_authorization FOR EACH ROW EXECUTE FUNCTION lomi_host_authorization_guard();
CREATE FUNCTION lomi_host_refresh_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE a public.host_authorization; h public.host_identity; epoch bigint; account_status text;
BEGIN
 IF TG_OP='UPDATE' THEN
   IF (NEW."tokenHash",NEW."authorizationId",NEW.rotation,NEW."expiresAt") IS DISTINCT FROM (OLD."tokenHash",OLD."authorizationId",OLD.rotation,OLD."expiresAt") OR
      (OLD."consumedOperationId" IS NOT NULL AND NEW."consumedOperationId" IS DISTINCT FROM OLD."consumedOperationId") THEN
     RAISE EXCEPTION 'immutable refresh credential tombstone' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
 END IF;
 SELECT * INTO a FROM public.host_authorization WHERE id=NEW."authorizationId" FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'unknown credential family' USING ERRCODE='23514'; END IF;
 SELECT u.status INTO account_status FROM public."user" u JOIN public.remote_account_identity r ON r."userId"=u.id WHERE r.id=a."accountId" FOR SHARE OF u;
 SELECT "authorizationEpoch" INTO epoch FROM public.remote_account_identity WHERE id=a."accountId" FOR SHARE;
 SELECT * INTO h FROM public.host_identity WHERE "hostId"=a."hostId" FOR SHARE;
 IF a.revoked OR account_status IS DISTINCT FROM 'active' OR epoch IS DISTINCT FROM a."approvedAccountEpoch" OR h."accessEpoch" IS DISTINCT FROM a."hostAccessEpoch" OR NEW.rotation<>a.rotation OR
    NEW."consumedOperationId" IS NOT NULL OR NEW."expiresAt"<=clock_timestamp() OR a."idleExpiresAt"<=clock_timestamp() THEN
   RAISE EXCEPTION 'credential requires current live family' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER host_refresh_guard BEFORE INSERT OR UPDATE ON host_refresh_credential FOR EACH ROW EXECUTE FUNCTION lomi_host_refresh_guard();
CREATE FUNCTION lomi_host_recovery_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE a public.host_authorization; e public.host_enrollment;
BEGIN
 IF TG_OP='DELETE' THEN
   -- A legitimate account cascade removes the parent family first.
   SELECT * INTO a FROM public.host_authorization WHERE id=OLD."authorizationId";
   IF FOUND AND NOT a.confirmed AND OLD."expiresAt">clock_timestamp() THEN
     RAISE EXCEPTION 'unconfirmed recovery must remain until expiry' USING ERRCODE='23514';
   END IF;
   RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' THEN
   IF (NEW."authorizationId",NEW.kind,NEW."operationId",NEW."requestHash",NEW."priorCredentialHash",NEW."expiresAt",NEW."createdAt") IS DISTINCT FROM
      (OLD."authorizationId",OLD.kind,OLD."operationId",OLD."requestHash",OLD."priorCredentialHash",OLD."expiresAt",OLD."createdAt") OR
      (NEW."sealedResponse" IS DISTINCT FROM OLD."sealedResponse" AND NEW."sealedResponse" IS NOT NULL) THEN
     RAISE EXCEPTION 'immutable recovery binding or ciphertext revival' USING ERRCODE='23514';
   END IF;
   IF OLD."sealedResponse" IS NOT NULL AND NEW."sealedResponse" IS NULL AND OLD."expiresAt">clock_timestamp() AND NOT EXISTS (SELECT FROM public.host_authorization WHERE id=OLD."authorizationId" AND confirmed) THEN
     RAISE EXCEPTION 'unconfirmed recovery ciphertext must remain until expiry' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
 END IF;
 SELECT * INTO a FROM public.host_authorization WHERE id=NEW."authorizationId" FOR UPDATE;
 IF NOT FOUND OR a.revoked THEN RAISE EXCEPTION 'recovery requires active family' USING ERRCODE='23514'; END IF;
 IF NEW.kind='exchange' THEN
   SELECT * INTO e FROM public.host_enrollment WHERE id=a."enrollmentId";
   IF NEW."operationId" IS DISTINCT FROM e."exchangeOperationId" THEN RAISE EXCEPTION 'exchange operation mismatch' USING ERRCODE='23514'; END IF;
 ELSIF NOT EXISTS (SELECT FROM public.host_refresh_credential WHERE "authorizationId"=a.id AND "tokenHash"=NEW."priorCredentialHash" AND "consumedOperationId"=NEW."operationId" AND rotation=a.rotation-1) THEN
   RAISE EXCEPTION 'rotation recovery requires exact consumed prior credential and operation' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER host_recovery_guard BEFORE INSERT OR UPDATE OR DELETE ON host_credential_recovery FOR EACH ROW EXECUTE FUNCTION lomi_host_recovery_guard();
REVOKE ALL ON FUNCTION lomi_host_identity_guard(),lomi_host_authorization_guard(),lomi_host_refresh_guard(),lomi_host_recovery_guard() FROM PUBLIC;
