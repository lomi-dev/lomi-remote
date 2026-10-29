-- Direct Better Auth consumers only. Legacy Remote/mobile derivatives require
-- their own explicit authority migration; account-read scope grants no authority.
CREATE TABLE public.consumer_authorization (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 "accountId" uuid NOT NULL, "userId" text NOT NULL,
 "accountSessionId" text NOT NULL,
 "originKind" text NOT NULL DEFAULT 'better_auth' CHECK ("originKind"='better_auth'),
 "originId" text NOT NULL CHECK ("originId"="accountSessionId"),
 "clientClass" text NOT NULL CHECK ("clientClass" IN ('web','desktop')),
 "canManageAccount" boolean NOT NULL DEFAULT true CHECK ("canManageAccount"),
 "authorizationEpoch" bigint NOT NULL CHECK ("authorizationEpoch">=1),
 "expiresAt" timestamptz(3) NOT NULL, revoked boolean NOT NULL DEFAULT false,
 FOREIGN KEY("accountId","userId") REFERENCES public.remote_account_identity(id,"userId") ON DELETE CASCADE ON UPDATE NO ACTION,
 FOREIGN KEY("accountSessionId","userId") REFERENCES public."session"(id,"userId") ON DELETE CASCADE ON UPDATE NO ACTION,
 FOREIGN KEY("accountSessionId","accountId","clientClass") REFERENCES public.remote_session_binding("sessionId","accountId","clientClass") ON DELETE CASCADE ON UPDATE NO ACTION,
 UNIQUE("originKind","originId")
);
CREATE INDEX "consumer_authorization_accountId_idx" ON public.consumer_authorization("accountId");
CREATE INDEX "consumer_authorization_expiresAt_idx" ON public.consumer_authorization("expiresAt");

CREATE TABLE public.consumer_window_challenge (
 "operationId" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 "consumerAuthorizationId" uuid NOT NULL REFERENCES public.consumer_authorization(id) ON DELETE CASCADE ON UPDATE NO ACTION,
 "windowIdentityId" uuid NOT NULL,
 "signedIdentity" jsonb NOT NULL,
 "identityFingerprint" bytea NOT NULL CHECK (octet_length("identityFingerprint")=32),
 nonce bytea NOT NULL CHECK (octet_length(nonce)=32),
 audience text NOT NULL CHECK (length(audience) BETWEEN 1 AND 256 AND audience ~ '^[!-~]+$'),
 "expiresAt" timestamptz(3) NOT NULL CHECK ("expiresAt"=date_trunc('second',"expiresAt")),
 "expectedChallenge" jsonb NOT NULL CHECK (jsonb_typeof("expectedChallenge")='object' AND octet_length("expectedChallenge"::text)<=8192 AND "expectedChallenge" ?& ARRAY['version','accountId','consumerAuthorizationId','accountSessionId','windowIdentityId','windowKeyFingerprint','operationId','nonce','audience','expiresAt'] AND "expectedChallenge" - ARRAY['version','accountId','consumerAuthorizationId','accountSessionId','windowIdentityId','windowKeyFingerprint','operationId','nonce','audience','expiresAt']='{}'::jsonb),
 "canonicalCbor" text NOT NULL CHECK (length("canonicalCbor") BETWEEN 2 AND 8192 AND "canonicalCbor" ~ '^(?:[0-9a-f]{2})+$'),
 consumed boolean NOT NULL DEFAULT false,
 "proofHash" bytea CHECK (octet_length("proofHash")=32),
 CHECK (consumed=("proofHash" IS NOT NULL)),
 CONSTRAINT consumer_window_challenge_signed_wire CHECK ((
  jsonb_typeof("signedIdentity")='object' AND
  "signedIdentity" ?& ARRAY['canonicalCbor','signature'] AND
  "signedIdentity" - ARRAY['canonicalCbor','signature']='{}'::jsonb AND
  jsonb_typeof("signedIdentity"->'canonicalCbor')='string' AND
  jsonb_typeof("signedIdentity"->'signature')='string' AND
  length("signedIdentity"->>'canonicalCbor') BETWEEN 2 AND 512 AND
  ("signedIdentity"->>'canonicalCbor') ~ '^(?:[0-9a-f]{2})+$' AND
  ("signedIdentity"->>'signature') ~ '^[0-9a-f]{128}$'
 ) IS TRUE),
 UNIQUE("operationId","consumerAuthorizationId","windowIdentityId")
);
CREATE INDEX "consumer_window_challenge_consumerAuthorizationId_idx" ON public.consumer_window_challenge("consumerAuthorizationId");
CREATE INDEX "consumer_window_challenge_expiresAt_idx" ON public.consumer_window_challenge("expiresAt");

CREATE TABLE public.consumer_window_identity (
 "windowIdentityId" uuid PRIMARY KEY,
 "consumerAuthorizationId" uuid NOT NULL,
 "operationId" uuid NOT NULL UNIQUE,
 UNIQUE("operationId","consumerAuthorizationId","windowIdentityId"),
 "signedIdentity" jsonb NOT NULL,
 "identityFingerprint" bytea NOT NULL CHECK (octet_length("identityFingerprint")=32),
 revoked boolean NOT NULL DEFAULT false,
 FOREIGN KEY("operationId","consumerAuthorizationId","windowIdentityId")
  REFERENCES public.consumer_window_challenge("operationId","consumerAuthorizationId","windowIdentityId") ON DELETE CASCADE ON UPDATE NO ACTION
);
CREATE INDEX "consumer_window_identity_consumerAuthorizationId_idx" ON public.consumer_window_identity("consumerAuthorizationId");

-- Invoker-only helper. Lock the authoritative rows through the transaction so
-- suspension, session/metadata changes and epoch fencing serialize with writes.
CREATE FUNCTION public.lomi_consumer_require_live(a public.consumer_authorization) RETURNS void
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE account_status text; epoch bigint; session_expiry timestamptz; metadata_kind text; binding_class text;
BEGIN
 SELECT status INTO account_status FROM public."user" WHERE id=a."userId" FOR SHARE;
 SELECT "authorizationEpoch" INTO epoch FROM public.remote_account_identity WHERE id=a."accountId" AND "userId"=a."userId" FOR SHARE;
 -- Better Auth timestamps are UTC without time zone, independent of caller TZ.
 SELECT "expiresAt" AT TIME ZONE 'UTC' INTO session_expiry FROM public."session" WHERE id=a."accountSessionId" AND "userId"=a."userId" FOR SHARE;
 SELECT kind INTO metadata_kind FROM public.session_metadata WHERE "sessionId"=a."accountSessionId" FOR SHARE;
 -- Binding rows are immutable. The composite FK and locked authorization
 -- serialize their parent cascades without granting UPDATE on server bindings.
 SELECT "clientClass" INTO binding_class FROM public.remote_session_binding WHERE "sessionId"=a."accountSessionId" AND "userId"=a."userId" AND "accountId"=a."accountId";
 IF a.revoked OR a."originKind" IS DISTINCT FROM 'better_auth' OR a."originId" IS DISTINCT FROM a."accountSessionId" OR NOT a."canManageAccount"
  OR account_status IS DISTINCT FROM 'active' OR epoch IS DISTINCT FROM a."authorizationEpoch"
  OR binding_class IS DISTINCT FROM a."clientClass"
  OR (CASE metadata_kind WHEN 'browser' THEN 'web' WHEN 'desktop' THEN 'desktop' ELSE NULL END) IS DISTINCT FROM a."clientClass"
  OR a."clientClass" NOT IN ('web','desktop') OR session_expiry IS NULL
  OR session_expiry<=clock_timestamp() OR a."expiresAt"<=clock_timestamp() OR a."expiresAt">session_expiry THEN
  RAISE EXCEPTION 'consumer requires live direct session and current account authority' USING ERRCODE='23514';
 END IF;
END $$;
CREATE FUNCTION public.lomi_consumer_authorization_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  IF (NEW.id,NEW."accountId",NEW."userId",NEW."accountSessionId",NEW."originKind",NEW."originId",NEW."clientClass",NEW."canManageAccount",NEW."authorizationEpoch",NEW."expiresAt") IS DISTINCT FROM
   (OLD.id,OLD."accountId",OLD."userId",OLD."accountSessionId",OLD."originKind",OLD."originId",OLD."clientClass",OLD."canManageAccount",OLD."authorizationEpoch",OLD."expiresAt") OR (OLD.revoked AND NOT NEW.revoked) THEN
   RAISE EXCEPTION 'immutable consumer origin or revocation rollback' USING ERRCODE='23514';
  END IF;
  -- Revocation remains possible after all parent authority has expired.
 ELSE
  PERFORM public.lomi_consumer_require_live(NEW);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER consumer_authorization_guard BEFORE INSERT OR UPDATE ON public.consumer_authorization
 FOR EACH ROW EXECUTE FUNCTION public.lomi_consumer_authorization_guard();

CREATE FUNCTION public.lomi_consumer_challenge_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE a public.consumer_authorization;
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.consumed OR NEW."proofHash" IS NOT NULL THEN RAISE EXCEPTION 'challenge must start unconsumed' USING ERRCODE='23514'; END IF;
 ELSE
  IF (NEW."operationId",NEW."consumerAuthorizationId",NEW."windowIdentityId",NEW."signedIdentity",NEW."identityFingerprint",NEW.nonce,NEW.audience,NEW."expiresAt",NEW."expectedChallenge",NEW."canonicalCbor") IS DISTINCT FROM
   (OLD."operationId",OLD."consumerAuthorizationId",OLD."windowIdentityId",OLD."signedIdentity",OLD."identityFingerprint",OLD.nonce,OLD.audience,OLD."expiresAt",OLD."expectedChallenge",OLD."canonicalCbor")
   OR (OLD.consumed AND (NEW.consumed,NEW."proofHash") IS DISTINCT FROM (OLD.consumed,OLD."proofHash")) THEN
   RAISE EXCEPTION 'immutable challenge or consumed proof' USING ERRCODE='23514';
  END IF;
 END IF;
 SELECT * INTO a FROM public.consumer_authorization WHERE id=NEW."consumerAuthorizationId" FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'unknown consumer authority' USING ERRCODE='23514'; END IF;
 PERFORM public.lomi_consumer_require_live(a);
 -- Retained native JSON must describe the authoritative row, never an unsigned
 -- alternative account/window/nonce. Canonical CBOR decoding remains Rust's job.
 IF NEW."expectedChallenge" IS DISTINCT FROM jsonb_build_object(
  'version',1,
  'accountId',(SELECT jsonb_agg(get_byte(decode(replace(a."accountId"::text,'-',''),'hex'),i) ORDER BY i) FROM generate_series(0,15) i),
  'consumerAuthorizationId',(SELECT jsonb_agg(get_byte(decode(replace(a.id::text,'-',''),'hex'),i) ORDER BY i) FROM generate_series(0,15) i),
  'accountSessionId',a."accountSessionId",
  'windowIdentityId',(SELECT jsonb_agg(get_byte(decode(replace(NEW."windowIdentityId"::text,'-',''),'hex'),i) ORDER BY i) FROM generate_series(0,15) i),
  'windowKeyFingerprint',(SELECT jsonb_agg(get_byte(NEW."identityFingerprint",i) ORDER BY i) FROM generate_series(0,31) i),
  'operationId',(SELECT jsonb_agg(get_byte(decode(replace(NEW."operationId"::text,'-',''),'hex'),i) ORDER BY i) FROM generate_series(0,15) i),
  'nonce',(SELECT jsonb_agg(get_byte(NEW.nonce,i) ORDER BY i) FROM generate_series(0,31) i),
  'audience',NEW.audience,
  'expiresAt',floor(extract(epoch FROM NEW."expiresAt"))::bigint::text
 ) THEN RAISE EXCEPTION 'challenge context must match authoritative row' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' AND (SELECT count(*) FROM public.consumer_window_challenge WHERE "consumerAuthorizationId"=a.id)>=64 THEN
  RAISE EXCEPTION 'consumer challenge resource limit' USING ERRCODE='23514';
 END IF;
 IF NEW."expiresAt"<=clock_timestamp() OR NEW."expiresAt">a."expiresAt" OR
  (TG_OP='INSERT' AND NEW."expiresAt">clock_timestamp()+interval '300 seconds') THEN
  RAISE EXCEPTION 'challenge requires bounded live expiry' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER consumer_challenge_guard BEFORE INSERT OR UPDATE ON public.consumer_window_challenge
 FOR EACH ROW EXECUTE FUNCTION public.lomi_consumer_challenge_guard();

CREATE FUNCTION public.lomi_consumer_window_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE a public.consumer_authorization; c public.consumer_window_challenge;
BEGIN
 IF TG_OP='UPDATE' THEN
  IF (NEW."windowIdentityId",NEW."consumerAuthorizationId",NEW."operationId",NEW."signedIdentity",NEW."identityFingerprint") IS DISTINCT FROM
   (OLD."windowIdentityId",OLD."consumerAuthorizationId",OLD."operationId",OLD."signedIdentity",OLD."identityFingerprint") OR (OLD.revoked AND NOT NEW.revoked) THEN
   RAISE EXCEPTION 'immutable finalized consumer window' USING ERRCODE='23514';
  END IF;
 ELSE
  SELECT * INTO a FROM public.consumer_authorization WHERE id=NEW."consumerAuthorizationId" FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'unknown consumer authority' USING ERRCODE='23514'; END IF;
  PERFORM public.lomi_consumer_require_live(a);
  IF (SELECT count(*) FROM public.consumer_window_identity WHERE "consumerAuthorizationId"=a.id)>=64 THEN
   RAISE EXCEPTION 'consumer window resource limit' USING ERRCODE='23514';
  END IF;
  SELECT * INTO c FROM public.consumer_window_challenge WHERE "operationId"=NEW."operationId" FOR SHARE;
  IF NOT FOUND OR NOT c.consumed OR c."proofHash" IS NULL OR c."expiresAt"<=clock_timestamp() OR NEW.revoked OR
   (NEW."consumerAuthorizationId",NEW."windowIdentityId",NEW."signedIdentity",NEW."identityFingerprint") IS DISTINCT FROM
   (c."consumerAuthorizationId",c."windowIdentityId",c."signedIdentity",c."identityFingerprint") THEN
   RAISE EXCEPTION 'window requires exact consumed live challenge' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER consumer_window_guard BEFORE INSERT OR UPDATE ON public.consumer_window_identity
 FOR EACH ROW EXECUTE FUNCTION public.lomi_consumer_window_guard();
REVOKE ALL ON FUNCTION public.lomi_consumer_require_live(public.consumer_authorization),public.lomi_consumer_authorization_guard(),public.lomi_consumer_challenge_guard(),public.lomi_consumer_window_guard() FROM PUBLIC;
