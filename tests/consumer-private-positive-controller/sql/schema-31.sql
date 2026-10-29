-- Requires approval-intent.candidate.sql; consent uses retained browser approval.
-- REVIEW CANDIDATE ONLY. NOT an applied Prisma migration; needs reviewed ops sealing.
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));

-- Strict successor guard: exact source-admitted predecessor, no target blessing.
-- Global lock is already held. Retain relation locks until this transaction ends.
LOCK TABLE public.consumer_authorization IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.remote_session_binding IN SHARE MODE;
DO $v2_predecessor_guard$
DECLARE expected jsonb := $v2_expected$[{"name":"consumer_authorization_accountSessionId_accountId_clientCl_fkey","type":"f","definition":"FOREIGN KEY (\"accountSessionId\", \"accountId\", \"clientClass\") REFERENCES remote_session_binding(\"sessionId\", \"accountId\", \"clientClass\") ON DELETE CASCADE","columns":["accountSessionId","accountId","clientClass"],"validated":true,"enforced":true,"deferrable":false,"deferred":false,"isLocal":true,"inheritCount":0,"noInherit":true,"hasParent":false,"period":false,"targetSchema":"public","targetRelation":"remote_session_binding","targetColumns":["sessionId","accountId","clientClass"],"updateAction":"a","deleteAction":"c","matchType":"s","deleteSetColumns":null,"indexSchema":"public","indexName":"remote_session_binding_sessionId_accountId_clientClass_key","indexValid":true,"indexReady":true,"indexUnique":true,"indexImmediate":true,"indexLive":true,"indexPrimary":false,"indexPredicate":null,"indexExpressions":null},{"name":"consumer_authorization_canManageAccount_check","type":"c","definition":"CHECK (\"canManageAccount\")","columns":["canManageAccount"],"validated":true,"enforced":true,"deferrable":false,"deferred":false,"isLocal":true,"inheritCount":0,"noInherit":false,"hasParent":false,"period":false},{"name":"consumer_authorization_check","type":"c","definition":"CHECK ((\"originId\" = \"accountSessionId\"))","columns":["originId","accountSessionId"],"validated":true,"enforced":true,"deferrable":false,"deferred":false,"isLocal":true,"inheritCount":0,"noInherit":false,"hasParent":false,"period":false},{"name":"consumer_authorization_clientClass_check","type":"c","definition":"CHECK ((\"clientClass\" = ANY (ARRAY['web'::text, 'desktop'::text])))","columns":["clientClass"],"validated":true,"enforced":true,"deferrable":false,"deferred":false,"isLocal":true,"inheritCount":0,"noInherit":false,"hasParent":false,"period":false},{"name":"consumer_authorization_originKind_check","type":"c","definition":"CHECK ((\"originKind\" = 'better_auth'::text))","columns":["originKind"],"validated":true,"enforced":true,"deferrable":false,"deferred":false,"isLocal":true,"inheritCount":0,"noInherit":false,"hasParent":false,"period":false}]$v2_expected$::jsonb; actual jsonb;
BEGIN
 SELECT coalesce(jsonb_agg(item ORDER BY item->>'name'),'[]'::jsonb) INTO actual
 FROM (
  SELECT jsonb_build_object(
   'name',c.conname,'type',c.contype,'definition',pg_get_constraintdef(c.oid,false),
   'columns',(SELECT jsonb_agg(a.attname ORDER BY k.n) FROM unnest(c.conkey) WITH ORDINALITY k(num,n)
     JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.num AND NOT a.attisdropped),
   'validated',c.convalidated,'enforced',c.conenforced,'deferrable',c.condeferrable,'deferred',c.condeferred,
   'isLocal',c.conislocal,'inheritCount',c.coninhcount,'noInherit',c.connoinherit,
   'hasParent',c.conparentid<>0,'period',c.conperiod)
   || CASE WHEN c.contype='f' THEN jsonb_build_object(
    'targetSchema',tn.nspname,'targetRelation',t.relname,
    'targetColumns',(SELECT jsonb_agg(a.attname ORDER BY k.n) FROM unnest(c.confkey) WITH ORDINALITY k(num,n)
      JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.num AND NOT a.attisdropped),
    'updateAction',c.confupdtype,'deleteAction',c.confdeltype,'matchType',c.confmatchtype,
    'deleteSetColumns',(SELECT jsonb_agg(a.attname ORDER BY k.n) FROM unnest(c.confdelsetcols) WITH ORDINALITY k(num,n)
      JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.num AND NOT a.attisdropped),
    'indexSchema',ixn.nspname,'indexName',ix.relname,'indexValid',i.indisvalid,'indexReady',i.indisready,
    'indexUnique',i.indisunique,'indexImmediate',i.indimmediate,'indexLive',i.indislive,
    'indexPrimary',i.indisprimary,'indexPredicate',pg_get_expr(i.indpred,i.indrelid,false),
    'indexExpressions',pg_get_expr(i.indexprs,i.indrelid,false)) ELSE '{}'::jsonb END AS item
  FROM pg_constraint c
  LEFT JOIN pg_class t ON t.oid=c.confrelid LEFT JOIN pg_namespace tn ON tn.oid=t.relnamespace
  LEFT JOIN pg_class ix ON ix.oid=c.conindid LEFT JOIN pg_namespace ixn ON ixn.oid=ix.relnamespace
  LEFT JOIN pg_index i ON i.indexrelid=c.conindid
  WHERE c.conrelid='public.consumer_authorization'::regclass AND (
   c.conname IN ('consumer_authorization_originKind_check','consumer_authorization_check',
    'consumer_authorization_clientClass_check','consumer_authorization_canManageAccount_check',
    'consumer_authorization_accountSessionId_accountId_clientCl_fkey')
   OR (c.contype='c' AND c.conkey && ARRAY(SELECT attnum FROM pg_attribute
      WHERE attrelid=c.conrelid AND attname IN ('accountSessionId','canManageAccount','clientClass','originId','originKind')
      AND NOT attisdropped)::smallint[])
   OR (c.contype='f' AND (c.confrelid='public.remote_session_binding'::regclass
      OR EXISTS(SELECT FROM pg_attribute a WHERE a.attrelid=c.conrelid AND a.attnum=ANY(c.conkey)
        AND a.attname IN ('originKind','originId','clientClass','canManageAccount') AND NOT a.attisdropped)
      OR ARRAY(SELECT a.attname::text FROM unnest(c.conkey) k(num) JOIN pg_attribute a
        ON a.attrelid=c.conrelid AND a.attnum=k.num AND NOT a.attisdropped ORDER BY a.attname)
        =ARRAY['accountId','accountSessionId','clientClass']::text[])))
 ) measured;
 IF actual IS DISTINCT FROM expected THEN
  RAISE EXCEPTION 'v2 predecessor contract mismatch; no DDL admitted' USING ERRCODE='55000';
 END IF;
END $v2_predecessor_guard$;

-- Existing scalar IDs are text. No conversion of Better Auth parents to UUID.
ALTER TABLE public.remote_service_authorization ADD CONSTRAINT derivative_service_owner_key UNIQUE(id,"userId","sourceSessionId");
ALTER TABLE public.remote_web_session ADD CONSTRAINT derivative_web_owner_key UNIQUE(id,"userId","sourceSessionId","authorizationId");
ALTER TABLE public.mobile_session ADD CONSTRAINT derivative_mobile_owner_key UNIQUE(id,"userId","sourceSessionId","authorizationId");

-- Explicit INSERT-only birth markers. Updating xmin/createdAt is not proof of
-- fresh login. No existing row is made eligible by this additive migration.
ALTER TABLE public.remote_service_authorization ADD COLUMN "consumerV3BirthXid" bigint;
ALTER TABLE public.remote_web_session ADD COLUMN "consumerV3BirthXid" bigint;
ALTER TABLE public.mobile_session ADD COLUMN "consumerV3BirthXid" bigint;
CREATE FUNCTION public.lomi_derivative_birth_guard_v2() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE source_row record; h public.consumer_approval_intent; stamp timestamptz;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 stamp:=clock_timestamp();
 IF TG_OP='UPDATE' THEN
  IF (NEW.id,NEW."userId",NEW."sourceSessionId",NEW."createdAt",NEW."consumerV3BirthXid",NEW."consumerApprovalId") IS DISTINCT FROM
     (OLD.id,OLD."userId",OLD."sourceSessionId",OLD."createdAt",OLD."consumerV3BirthXid",OLD."consumerApprovalId") THEN
   RAISE EXCEPTION 'immutable derivative birth, approval and ownership' USING ERRCODE='23514'; END IF;
  IF TG_TABLE_NAME='remote_service_authorization' THEN
   IF (NEW.scope,NEW.version,NEW."clientId") IS DISTINCT FROM (OLD.scope,OLD.version,OLD."clientId") THEN
    RAISE EXCEPTION 'service authorization cannot be upgraded in place' USING ERRCODE='23514'; END IF;
  ELSE
   IF NEW."authorizationId" IS DISTINCT FROM OLD."authorizationId" THEN
    RAISE EXCEPTION 'immutable actual service authorization' USING ERRCODE='23514'; END IF;
  END IF;
  IF OLD."revokedAt" IS NOT NULL AND NEW."revokedAt" IS DISTINCT FROM OLD."revokedAt" THEN
   RAISE EXCEPTION 'derivative revocation is terminal' USING ERRCODE='23514'; END IF;
 ELSE
  IF TG_TABLE_NAME='remote_service_authorization' THEN
   IF NEW.scope='remote:account:read remote:v3:consumer' THEN
    SELECT * INTO h FROM public.consumer_approval_intent WHERE id=NEW."consumerApprovalId";
    IF NOT FOUND OR NEW.version<>1 OR h."consumedAt" IS NULL OR h."consumedXid" IS DISTINCT FROM txid_current()
     OR h."expiresAt"<=stamp OR (h."codeExpiresAt" AT TIME ZONE 'UTC')<=stamp
     OR (NEW."expiresAt" AT TIME ZONE 'UTC') IS DISTINCT FROM h."serviceDeadline" OR NEW."revokedAt" IS NOT NULL THEN
     RAISE EXCEPTION 'fresh service requires this transaction exact consumed approval' USING ERRCODE='23514'; END IF;
    NEW."consumerV3BirthXid":=txid_current();
   ELSE
    IF NEW."consumerApprovalId" IS NOT NULL THEN RAISE EXCEPTION 'legacy service cannot claim approval' USING ERRCODE='23514'; END IF;
    NEW."consumerV3BirthXid":=NULL;
   END IF;
  ELSE
   SELECT "consumerV3BirthXid","consumerApprovalId",scope INTO source_row FROM public.remote_service_authorization WHERE id=NEW."authorizationId";
   IF source_row.scope='remote:account:read remote:v3:consumer' THEN
    SELECT * INTO h FROM public.consumer_approval_intent WHERE id=NEW."consumerApprovalId";
    IF NOT FOUND OR source_row."consumerV3BirthXid" IS DISTINCT FROM txid_current() OR source_row."consumerApprovalId" IS DISTINCT FROM h.id
     OR h."consumedXid" IS DISTINCT FROM txid_current() OR h."consumedAt" IS NULL OR h."expiresAt"<=stamp
     OR (TG_TABLE_NAME='remote_web_session' AND h."actualKind"<>'remote_web') OR (TG_TABLE_NAME='mobile_session' AND h."actualKind"<>'mobile')
     OR (NEW."expiresAt" AT TIME ZONE 'UTC') IS DISTINCT FROM h."actualDeadline"
     OR (NEW."idleExpiresAt" AT TIME ZONE 'UTC') IS DISTINCT FROM h."actualIdleDeadline" OR NEW."revokedAt" IS NOT NULL THEN
     RAISE EXCEPTION 'fresh actual principal requires exact approval and original ceilings' USING ERRCODE='23514'; END IF;
    NEW."consumerV3BirthXid":=txid_current();
   ELSE
    IF NEW."consumerApprovalId" IS NOT NULL THEN RAISE EXCEPTION 'legacy principal cannot claim approval' USING ERRCODE='23514'; END IF;
    NEW."consumerV3BirthXid":=NULL;
   END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER derivative_service_birth_guard_v2 BEFORE INSERT OR UPDATE ON public.remote_service_authorization FOR EACH ROW EXECUTE FUNCTION public.lomi_derivative_birth_guard_v2();
CREATE TRIGGER derivative_web_birth_guard_v2 BEFORE INSERT OR UPDATE ON public.remote_web_session FOR EACH ROW EXECUTE FUNCTION public.lomi_derivative_birth_guard_v2();
CREATE TRIGGER derivative_mobile_birth_guard_v2 BEFORE INSERT OR UPDATE ON public.mobile_session FOR EACH ROW EXECUTE FUNCTION public.lomi_derivative_birth_guard_v2();
REVOKE ALL ON FUNCTION public.lomi_derivative_birth_guard_v2() FROM PUBLIC;

CREATE TABLE public.consumer_derivative_consent (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 "approvalIntentId" uuid NOT NULL UNIQUE,
 "accountId" uuid NOT NULL, "userId" text NOT NULL, "accountSessionId" text NOT NULL,
 "actualKind" text NOT NULL CHECK ("actualKind" IN ('remote_web','mobile')),
 "actualId" text NOT NULL CHECK (length("actualId") BETWEEN 1 AND 128 AND "actualId" ~ '^[!-~]+$'),
 "webSessionId" text, "mobileSessionId" text,
 "serviceAuthorizationId" text NOT NULL,
 "consentVersion" integer NOT NULL CHECK ("consentVersion"=1),
 scope text NOT NULL CHECK (scope='remote:account:read remote:v3:consumer'),
 "authorizationEpoch" bigint NOT NULL CHECK ("authorizationEpoch">=1),
 "consentedAt" timestamptz(3) NOT NULL,
 "birthXid" bigint NOT NULL DEFAULT txid_current(),
 -- Snapshot ceilings: immutable even when legacy renewal extends parent rows.
 "parentDeadline" timestamptz(3) NOT NULL,
 "serviceDeadline" timestamptz(3) NOT NULL,
 "actualDeadline" timestamptz(3) NOT NULL,
 "actualIdleDeadline" timestamptz(3) NOT NULL,
 "expiresAt" timestamptz(3) NOT NULL,
 revoked boolean NOT NULL DEFAULT false,
 CHECK (("actualKind"='remote_web' AND "webSessionId"="actualId" AND "webSessionId" IS NOT NULL AND "mobileSessionId" IS NULL)
     OR ("actualKind"='mobile' AND "mobileSessionId"="actualId" AND "mobileSessionId" IS NOT NULL AND "webSessionId" IS NULL)),
 CHECK ("expiresAt">"consentedAt" AND "expiresAt"=least("consentedAt"+interval '604800 seconds',"parentDeadline","serviceDeadline","actualDeadline")),
 CONSTRAINT derivative_consent_consumed_proof_exact FOREIGN KEY("approvalIntentId","birthXid")
  REFERENCES public.consumer_approval_consumed_proof("approvalIntentId","exchangeXid") ON DELETE CASCADE ON UPDATE NO ACTION,
 CONSTRAINT derivative_consent_approval_exact FOREIGN KEY("approvalIntentId","accountId","userId","accountSessionId","actualKind","actualId","serviceAuthorizationId","authorizationEpoch","consentedAt","parentDeadline","serviceDeadline","actualDeadline","actualIdleDeadline","expiresAt",scope,"consentVersion")
  REFERENCES public.consumer_approval_intent(id,"accountId","userId","accountSessionId","actualKind","actualId","serviceAuthorizationId","authorizationEpoch","approvedAt","parentDeadline","serviceDeadline","actualDeadline","actualIdleDeadline","expiresAt",scope,"consentVersion") ON DELETE CASCADE ON UPDATE NO ACTION,
 FOREIGN KEY("accountId","userId") REFERENCES public.remote_account_identity(id,"userId") ON DELETE CASCADE ON UPDATE NO ACTION,
 FOREIGN KEY("accountSessionId","userId") REFERENCES public."session"(id,"userId") ON DELETE CASCADE ON UPDATE NO ACTION,
 FOREIGN KEY("serviceAuthorizationId","userId","accountSessionId") REFERENCES public.remote_service_authorization(id,"userId","sourceSessionId") ON DELETE CASCADE ON UPDATE NO ACTION,
 FOREIGN KEY("webSessionId","userId","accountSessionId","serviceAuthorizationId") REFERENCES public.remote_web_session(id,"userId","sourceSessionId","authorizationId") ON DELETE CASCADE ON UPDATE NO ACTION,
 FOREIGN KEY("mobileSessionId","userId","accountSessionId","serviceAuthorizationId") REFERENCES public.mobile_session(id,"userId","sourceSessionId","authorizationId") ON DELETE CASCADE ON UPDATE NO ACTION,
 UNIQUE("actualKind","actualId"),
 UNIQUE(id,"accountId","userId","accountSessionId","actualKind","actualId","serviceAuthorizationId","authorizationEpoch","expiresAt")
);
-- Only missing leading cascade keys. Approval identity already has UNIQUE;
-- actual kind/id and C origins already have their existing unique indexes.
CREATE INDEX consumer_derivative_consent_parent_idx ON public.consumer_derivative_consent("accountSessionId");
CREATE INDEX consumer_derivative_consent_account_idx ON public.consumer_derivative_consent("accountId");
CREATE INDEX consumer_derivative_consent_service_idx ON public.consumer_derivative_consent("serviceAuthorizationId");
CREATE INDEX consumer_derivative_consent_web_idx ON public.consumer_derivative_consent("webSessionId");
CREATE INDEX consumer_derivative_consent_mobile_idx ON public.consumer_derivative_consent("mobileSessionId");
REVOKE ALL ON TABLE public.consumer_derivative_consent FROM PUBLIC;

ALTER TABLE public.consumer_authorization ADD COLUMN "consentId" uuid,
 ADD COLUMN "serviceAuthorizationId" text;
-- Preserve the original direct constraints as an explicit disjoint branch.
-- Generated names below belong to 004. Reject any unexpected deployment shape.
ALTER TABLE public.consumer_authorization
 DROP CONSTRAINT "consumer_authorization_originKind_check",
 DROP CONSTRAINT "consumer_authorization_check",
 DROP CONSTRAINT "consumer_authorization_clientClass_check",
 DROP CONSTRAINT "consumer_authorization_canManageAccount_check";
-- Drop only the exact FK already admitted by the locked predecessor guard.
ALTER TABLE public.consumer_authorization
 DROP CONSTRAINT "consumer_authorization_accountSessionId_accountId_clientCl_fkey";
ALTER TABLE public.consumer_authorization
 ADD CONSTRAINT consumer_origin_disjoint CHECK (
  ("originKind"='better_auth' AND "originId"="accountSessionId" AND "clientClass" IN ('web','desktop') AND "canManageAccount" AND "consentId" IS NULL AND "serviceAuthorizationId" IS NULL)
  OR ("originKind" IN ('remote_web','mobile') AND "clientClass"=CASE "originKind" WHEN 'remote_web' THEN 'web' ELSE 'mobile' END
   AND NOT "canManageAccount" AND "consentId" IS NOT NULL AND "serviceAuthorizationId" IS NOT NULL)),
 ADD CONSTRAINT consumer_derivative_consent_exact FOREIGN KEY("consentId","accountId","userId","accountSessionId","originKind","originId","serviceAuthorizationId","authorizationEpoch","expiresAt")
  REFERENCES public.consumer_derivative_consent(id,"accountId","userId","accountSessionId","actualKind","actualId","serviceAuthorizationId","authorizationEpoch","expiresAt") ON DELETE CASCADE ON UPDATE NO ACTION;
-- Direct-binding class equality is still enforced by the unchanged direct
-- require_live branch; this parent FK retains cascade/identity binding for both.
ALTER TABLE public.remote_session_binding ADD CONSTRAINT derivative_parent_binding_key UNIQUE("sessionId","accountId");
ALTER TABLE public.consumer_authorization ADD CONSTRAINT consumer_parent_binding FOREIGN KEY("accountSessionId","accountId")
 REFERENCES public.remote_session_binding("sessionId","accountId") ON DELETE CASCADE ON UPDATE NO ACTION;

CREATE TYPE public.lomi_consumer_assertion_v2 AS (
 version integer,
 "accountId" uuid, "consumerAuthorizationId" uuid, "accountSessionId" text,
 "clientClass" text, "authorizationEpoch" bigint, "expiresAtMs" bigint, "canManageAccount" boolean,
 "actualKind" text, "actualId" text, "serviceAuthorizationId" text,
 "consentId" uuid, "consentVersion" integer, "credentialHash" bytea
);
REVOKE ALL ON TYPE public.lomi_consumer_assertion_v2 FROM PUBLIC;

-- Immutable tombstone, including no changes to snapshot ceilings.
CREATE FUNCTION public.lomi_derivative_consent_guard_v2() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE d record; s record; a record; h public.consumer_approval_intent; epoch bigint; stamp timestamptz;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 stamp:=clock_timestamp();
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'revoked') IS DISTINCT FROM (to_jsonb(OLD)-'revoked') OR (OLD.revoked AND NOT NEW.revoked) THEN
   RAISE EXCEPTION 'immutable derivative consent or revocation rollback' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO h FROM public.consumer_approval_intent WHERE id=NEW."approvalIntentId";
 IF NOT FOUND OR h."consumedAt" IS NULL OR h."consumedXid" IS DISTINCT FROM txid_current() OR h."expiresAt"<=stamp
  OR (h."codeExpiresAt" AT TIME ZONE 'UTC')<=stamp OR NEW."consentedAt" IS DISTINCT FROM h."approvedAt"
  OR NEW."parentDeadline" IS DISTINCT FROM h."parentDeadline" OR NEW."serviceDeadline" IS DISTINCT FROM h."serviceDeadline"
  OR NEW."actualDeadline" IS DISTINCT FROM h."actualDeadline" OR NEW."actualIdleDeadline" IS DISTINCT FROM h."actualIdleDeadline"
  OR NEW."expiresAt" IS DISTINCT FROM h."expiresAt" THEN
  RAISE EXCEPTION 'final consent requires exact retained browser approval, never exchange resampling' USING ERRCODE='23514'; END IF;
 SELECT rs.* INTO a FROM public.remote_service_authorization rs WHERE id=NEW."serviceAuthorizationId";
 SELECT p."expiresAt" AT TIME ZONE 'UTC' AS expiry,m.kind,b."clientClass",u.status INTO s
 FROM public."session" p JOIN public.session_metadata m ON m."sessionId"=p.id
 JOIN public.remote_session_binding b ON b."sessionId"=p.id AND b."accountId"=NEW."accountId" AND b."userId"=NEW."userId"
 JOIN public."user" u ON u.id=p."userId" WHERE p.id=NEW."accountSessionId" AND p."userId"=NEW."userId";
 IF NEW."actualKind"='remote_web' THEN
  SELECT "expiresAt","idleExpiresAt","revokedAt","consumerV3BirthXid","consumerApprovalId" INTO d FROM public.remote_web_session WHERE id=NEW."actualId";
 ELSE
  SELECT "expiresAt","idleExpiresAt","revokedAt","consumerV3BirthXid","consumerApprovalId" INTO d FROM public.mobile_session WHERE id=NEW."actualId";
 END IF;
 SELECT "authorizationEpoch" INTO epoch FROM public.remote_account_identity WHERE id=NEW."accountId" AND "userId"=NEW."userId";
 IF s.status IS DISTINCT FROM 'active' OR s.kind IS DISTINCT FROM 'browser' OR s."clientClass" IS DISTINCT FROM 'web'
  OR s.expiry IS NULL OR s.expiry<NEW."expiresAt" -- current shortening may deny; extension cannot raise snapshots
  OR a.id IS NULL OR d."consumerV3BirthXid" IS DISTINCT FROM txid_current() OR a."consumerV3BirthXid" IS DISTINCT FROM txid_current()
  OR a."consumerApprovalId" IS DISTINCT FROM h.id OR d."consumerApprovalId" IS DISTINCT FROM h.id
  OR a.version IS DISTINCT FROM 1 OR a.scope IS DISTINCT FROM NEW.scope OR a."revokedAt" IS NOT NULL OR d."revokedAt" IS NOT NULL
  OR NEW."birthXid" IS DISTINCT FROM txid_current() OR epoch IS DISTINCT FROM NEW."authorizationEpoch" OR NEW.revoked
  OR NEW."serviceDeadline" IS DISTINCT FROM (a."expiresAt" AT TIME ZONE 'UTC')
  OR NEW."actualDeadline" IS DISTINCT FROM (d."expiresAt" AT TIME ZONE 'UTC')
  OR NEW."actualIdleDeadline" IS DISTINCT FROM (d."idleExpiresAt" AT TIME ZONE 'UTC') THEN
  RAISE EXCEPTION 'fresh actual authority must satisfy the earlier approval ceilings' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER derivative_consent_guard_v2 BEFORE INSERT OR UPDATE ON public.consumer_derivative_consent FOR EACH ROW EXECUTE FUNCTION public.lomi_derivative_consent_guard_v2();
REVOKE ALL ON FUNCTION public.lomi_derivative_consent_guard_v2() FROM PUBLIC;
-- New objects are default-deny; no operational grants are included here.
-- GENERATED default-deny closure below.
DO $default_deny$
DECLARE role_name text; signature text;
BEGIN
 FOREACH role_name IN ARRAY ARRAY['lomi_runtime','lomi_remote_api','lomi_remote_exchange','lomi_remote_runtime_owner','lomi_remote_inventory_owner','lomi_remote_pairing_write_owner'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=role_name) THEN
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_derivative_birth_guard_v2() FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_derivative_consent_guard_v2() FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON TABLE public.consumer_derivative_consent FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON TYPE public.lomi_consumer_assertion_v2 FROM %I',role_name);
  END IF;
 END LOOP;
END $default_deny$;
COMMIT;
