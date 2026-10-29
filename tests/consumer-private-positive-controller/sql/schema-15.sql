-- Public finalized identity is published only after canonical Rust verification
-- by the Auth coordinator. Retained commitments and legacy rows stay unchanged.
ALTER TABLE public.host_identity ADD COLUMN "finalizedIdentity" jsonb;
ALTER TABLE public.host_identity ADD CONSTRAINT host_identity_finalized_wire CHECK (
 "finalizedIdentity" IS NULL OR (
  jsonb_typeof("finalizedIdentity")='object' AND
  "finalizedIdentity" ?& ARRAY['canonicalCbor','signature'] AND
  "finalizedIdentity" - ARRAY['canonicalCbor','signature'] = '{}'::jsonb AND
  jsonb_typeof("finalizedIdentity"->'canonicalCbor')='string' AND
  jsonb_typeof("finalizedIdentity"->'signature')='string' AND
  length("finalizedIdentity"->>'canonicalCbor') BETWEEN 2 AND 512 AND
  ("finalizedIdentity"->>'canonicalCbor') ~ '^(?:[0-9a-f]{2})+$' AND
  length("finalizedIdentity"->>'signature')=128 AND
  ("finalizedIdentity"->>'signature') ~ '^[0-9a-f]{128}$'
 ));
CREATE FUNCTION public.lomi_host_finalized_identity_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW."finalizedIdentity" IS NOT NULL THEN
   RAISE EXCEPTION 'finalized identity requires registration' USING ERRCODE='23514';
  END IF;
 ELSIF NEW."finalizedIdentity" IS DISTINCT FROM OLD."finalizedIdentity" THEN
  IF OLD."finalizedIdentity" IS NOT NULL OR NEW."finalizedIdentity" IS NULL THEN
   RAISE EXCEPTION 'immutable finalized host identity' USING ERRCODE='23514';
  END IF;
  IF NOT EXISTS (
   SELECT FROM public.host_authorization a
   JOIN public.remote_account_identity r ON r.id=a."accountId"
   JOIN public."user" u ON u.id=r."userId"
   WHERE a."hostId"=OLD."hostId" AND a."accountId"=OLD."accountId"
    AND NOT a.revoked AND u.status='active'
    AND a."approvedAccountEpoch"=r."authorizationEpoch"
    AND a."hostAccessEpoch"=OLD."accessEpoch"
    AND a."accessExpiresAt">clock_timestamp() AND a."idleExpiresAt">clock_timestamp()
  ) THEN RAISE EXCEPTION 'finalized identity requires live host authorization' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER host_finalized_identity_guard BEFORE INSERT OR UPDATE ON public.host_identity
 FOR EACH ROW EXECUTE FUNCTION public.lomi_host_finalized_identity_guard();
CREATE FUNCTION public.lomi_host_finalized_authorization_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
 -- Revocation remains available after expiry, suspension and epoch fencing.
 IF (NEW.confirmed AND NOT OLD.confirmed) OR NEW.rotation<>OLD.rotation THEN
  IF NEW.revoked OR (NEW.rotation<>OLD.rotation AND NOT NEW.confirmed) OR NOT EXISTS (
   SELECT FROM public.host_identity h
   JOIN public.remote_account_identity r ON r.id=NEW."accountId"
   JOIN public."user" u ON u.id=r."userId"
   WHERE h."hostId"=NEW."hostId" AND h."accountId"=NEW."accountId"
    AND h."finalizedIdentity" IS NOT NULL AND u.status='active'
    AND NEW."approvedAccountEpoch"=r."authorizationEpoch"
    AND NEW."hostAccessEpoch"=h."accessEpoch"
    AND NEW."idleExpiresAt">clock_timestamp() AND OLD."idleExpiresAt">clock_timestamp()
    AND (NEW.rotation<>OLD.rotation OR NEW."accessExpiresAt">clock_timestamp())
  ) THEN RAISE EXCEPTION 'confirmation and rotation require finalized live identity' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER host_finalized_authorization_guard BEFORE UPDATE ON public.host_authorization
 FOR EACH ROW EXECUTE FUNCTION public.lomi_host_finalized_authorization_guard();
REVOKE ALL ON FUNCTION public.lomi_host_finalized_identity_guard(), public.lomi_host_finalized_authorization_guard() FROM PUBLIC;
