-- Only after the additive migration. Execute as the database owner; no passwords.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO lomi_remote_api, lomi_remote_exchange;
GRANT SELECT (id, name, email, image, status) ON public."user" TO lomi_remote_api, lomi_remote_exchange;
GRANT SELECT (id, "userId", "expiresAt") ON public."session" TO lomi_remote_api, lomi_remote_exchange;
GRANT SELECT, INSERT, UPDATE ON public.remote_login_attempt TO lomi_remote_api;
GRANT SELECT, UPDATE ON public.remote_service_authorization, public.remote_web_session TO lomi_remote_api;
GRANT SELECT, INSERT, UPDATE ON public."rateLimit" TO lomi_remote_api;
GRANT SELECT, UPDATE ON public.remote_login_attempt, public.remote_identity_code TO lomi_remote_exchange;
GRANT SELECT, INSERT ON public.remote_service_authorization, public.remote_web_session TO lomi_remote_exchange;
-- Authenticated renewal may extend only validity deadlines. Prisma maintains
-- session.updatedAt; source tokens, ownership, scope and revocation stay sealed.
GRANT UPDATE ("expiresAt", "updatedAt") ON public."session" TO lomi_remote_exchange;
GRANT UPDATE ("expiresAt") ON public.remote_service_authorization TO lomi_remote_exchange;
GRANT UPDATE ("expiresAt", "idleExpiresAt") ON public.remote_web_session TO lomi_remote_exchange;
GRANT SELECT, INSERT, UPDATE ON public."rateLimit" TO lomi_remote_exchange;
-- Remote readiness checks validate schema and permissions of every new table.
GRANT SELECT ON public.remote_identity_code TO lomi_remote_api;
-- Main identity retains its existing role for browser handoff and maintenance.
GRANT SELECT, INSERT, UPDATE, DELETE ON public.remote_login_attempt, public.remote_identity_code,
  public.remote_service_authorization, public.remote_web_session TO lomi_runtime;

-- Workspace inventory/scope/purpose migration adds columns to these existing
-- Remote tables; table grants cover them without expanding identity access.
GRANT SELECT ("sessionId", kind) ON public.session_metadata TO lomi_remote_api;
GRANT SELECT, INSERT, UPDATE ON public.remote_host, public.remote_pairing, public.remote_grant,
 public.remote_channel, public.remote_relay_ticket, public.remote_relay_owner TO lomi_remote_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.remote_host, public.remote_pairing, public.remote_grant,
 public.remote_channel, public.remote_relay_ticket, public.remote_relay_owner TO lomi_runtime;

-- Mobile credentials are issued only by identity. Remote can read the current
-- opaque access principal but cannot create or rotate its credentials.
GRANT SELECT ON public.mobile_session TO lomi_remote_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.mobile_login, public.mobile_session,
 public.mobile_refresh TO lomi_runtime;
GRANT DELETE ON public.remote_relay_ticket TO lomi_runtime;

-- E2 mappings are sealed even after broad legacy/default table grants.
REVOKE ALL ON remote_account_identity, remote_session_binding, host_enrollment, host_bootstrap FROM lomi_runtime;
GRANT SELECT ON remote_account_identity, remote_session_binding, host_enrollment, host_bootstrap TO lomi_runtime;
GRANT INSERT ("userId") ON remote_account_identity TO lomi_runtime;
GRANT UPDATE ("authorizationEpoch") ON remote_account_identity TO lomi_runtime;
GRANT INSERT ON remote_session_binding, host_enrollment, host_bootstrap TO lomi_runtime;
GRANT UPDATE ON host_enrollment, host_bootstrap TO lomi_runtime;
GRANT DELETE ON host_bootstrap TO lomi_runtime;

-- Host credentials remain private to identity; Remote receives no secret grants.
REVOKE ALL ON public.host_identity, public.host_authorization, public.host_refresh_credential, public.host_credential_recovery FROM lomi_runtime;
GRANT SELECT, INSERT ON public.host_identity, public.host_authorization, public.host_refresh_credential, public.host_credential_recovery TO lomi_runtime;
GRANT UPDATE ("accessEpoch", "finalizedIdentity") ON public.host_identity TO lomi_runtime;
GRANT UPDATE (revoked, confirmed, rotation, "accessHash", "accessExpiresAt", "idleExpiresAt") ON public.host_authorization TO lomi_runtime;
GRANT UPDATE ("consumedOperationId") ON public.host_refresh_credential TO lomi_runtime;
GRANT UPDATE ("sealedResponse"), DELETE ON public.host_credential_recovery TO lomi_runtime;
REVOKE ALL ON public.host_identity, public.host_authorization, public.host_refresh_credential, public.host_credential_recovery FROM lomi_remote_api, lomi_remote_exchange;

-- Consumer authority is private to Auth. Seal broad/default legacy grants on
-- every reapplication; retained origins/challenges cannot be deleted by Auth.
REVOKE ALL ON public.consumer_authorization, public.consumer_window_challenge, public.consumer_window_identity FROM lomi_runtime, lomi_remote_api, lomi_remote_exchange;
GRANT SELECT, INSERT ON public.consumer_authorization, public.consumer_window_challenge, public.consumer_window_identity TO lomi_runtime;
GRANT UPDATE (revoked) ON public.consumer_authorization, public.consumer_window_identity TO lomi_runtime;
GRANT UPDATE (consumed, "proofHash") ON public.consumer_window_challenge TO lomi_runtime;
GRANT EXECUTE ON FUNCTION public.lomi_consumer_require_live(public.consumer_authorization) TO lomi_runtime;

-- Operator-only runtime sealing. 005 never requires migrator CREATEROLE or
-- membership in this owner. The admin bootstrap runs this after migrations.
DO $runtime_owner$
DECLARE r record; signature text; owner_name text;
BEGIN
 IF NOT current_setting('is_superuser')::boolean THEN RAISE EXCEPTION 'runtime sealing requires operator'; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='lomi_remote_runtime_owner') THEN
  CREATE ROLE lomi_remote_runtime_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 SELECT * INTO STRICT r FROM pg_roles WHERE rolname='lomi_remote_runtime_owner';
 IF r.rolcanlogin OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR
  EXISTS(SELECT FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid) THEN
  RAISE EXCEPTION 'unexpected runtime execution owner';
 END IF;
 GRANT USAGE ON SCHEMA public TO lomi_remote_runtime_owner;
 GRANT SELECT ON public.host_identity,public.host_authorization,public.remote_account_identity TO lomi_remote_runtime_owner;
 GRANT SELECT(id,status) ON public."user" TO lomi_remote_runtime_owner;
 GRANT UPDATE("accessEpoch") ON public.host_identity TO lomi_remote_runtime_owner;
 GRANT UPDATE("hostAccessEpoch") ON public.host_authorization TO lomi_remote_runtime_owner;
 GRANT SELECT,INSERT,UPDATE,DELETE ON public.host_runtime,public.host_runtime_transition TO lomi_remote_runtime_owner;
 GRANT EXECUTE ON FUNCTION public.lomi_host_runtime_publication_valid(jsonb) TO lomi_remote_runtime_owner;
 -- ALTER OWNER needs schema CREATE on the destination role only while this
 -- administrator transaction executes. No application can SET ROLE to it.
 GRANT CREATE ON SCHEMA public TO lomi_remote_runtime_owner;
 FOREACH signature IN ARRAY ARRAY[
  'public.lomi_host_runtime_authority(uuid,bytea)',
  'public.lomi_host_access_lookup(uuid,bytea)',
  'public.lomi_host_runtime_get(uuid,bytea)',
  'public.lomi_host_runtime_claim(uuid,bytea,uuid,bigint,bigint)',
  'public.lomi_host_runtime_heartbeat(uuid,bytea,uuid,bigint,bigint)',
  'public.lomi_host_runtime_publish(uuid,bytea,uuid,bigint,bigint,bigint,bigint,jsonb)'
 ] LOOP
  SELECT pg_get_userbyid(proowner) INTO STRICT owner_name FROM pg_proc WHERE oid=signature::regprocedure;
  IF owner_name NOT IN ('lomi_migrator','lomi_remote_runtime_owner',current_user) THEN RAISE EXCEPTION 'unexpected runtime function owner'; END IF;
  EXECUTE format('ALTER FUNCTION %s OWNER TO lomi_remote_runtime_owner',signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange',signature);
 END LOOP;
 REVOKE CREATE ON SCHEMA public FROM lomi_remote_runtime_owner;
END $runtime_owner$;
REVOKE ALL ON public.host_runtime,public.host_runtime_transition FROM lomi_runtime,lomi_remote_api,lomi_remote_exchange;
REVOKE ALL ON FUNCTION public.lomi_host_runtime_publication_valid(jsonb) FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange;
GRANT EXECUTE ON FUNCTION public.lomi_host_access_lookup(uuid,bytea),public.lomi_host_runtime_get(uuid,bytea),
 public.lomi_host_runtime_claim(uuid,bytea,uuid,bigint,bigint),public.lomi_host_runtime_heartbeat(uuid,bytea,uuid,bigint,bigint),
 public.lomi_host_runtime_publish(uuid,bytea,uuid,bigint,bigint,bigint,bigint,jsonb) TO lomi_remote_api;

-- Operator-only read-only consumer inventory owner. Session-token access never
-- reaches the distinct epoch-mutating host-runtime execution owner.
DO $inventory_owner$
DECLARE r record; table_columns record; signature text:='public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea)'; owner_name text;
BEGIN
 IF NOT current_setting('is_superuser')::boolean THEN RAISE EXCEPTION 'inventory sealing requires operator'; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='lomi_remote_inventory_owner') THEN
  CREATE ROLE lomi_remote_inventory_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 SELECT * INTO STRICT r FROM pg_roles WHERE rolname='lomi_remote_inventory_owner';
 IF r.rolcanlogin OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR
  EXISTS(SELECT FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid) THEN
  RAISE EXCEPTION 'unexpected inventory execution owner'; END IF;
 GRANT USAGE ON SCHEMA public TO lomi_remote_inventory_owner;
 REVOKE ALL ON ALL TABLES IN SCHEMA public FROM lomi_remote_inventory_owner;
 -- Table REVOKE does not remove pre-existing column privileges. Seal those as
 -- well before granting the exact read columns, including on repeated runs.
 FOR table_columns IN
  SELECT c.oid::regclass AS relation,string_agg(quote_ident(a.attname),',' ORDER BY a.attnum) AS columns
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid
  WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f') AND a.attnum>0 AND NOT a.attisdropped GROUP BY c.oid
 LOOP
  EXECUTE format('REVOKE ALL (%s) ON TABLE %s FROM lomi_remote_inventory_owner',table_columns.columns,table_columns.relation);
 END LOOP;
 GRANT SELECT (id,"accountId","userId","accountSessionId","originKind","originId","clientClass","canManageAccount","authorizationEpoch","expiresAt",revoked) ON public.consumer_authorization TO lomi_remote_inventory_owner;
 GRANT SELECT (id,"userId","authorizationEpoch") ON public.remote_account_identity TO lomi_remote_inventory_owner;
 GRANT SELECT (id,status) ON public."user" TO lomi_remote_inventory_owner;
 GRANT SELECT (id,"userId",token,"expiresAt") ON public."session" TO lomi_remote_inventory_owner;
 GRANT SELECT ("sessionId","userId","accountId","clientClass") ON public.remote_session_binding TO lomi_remote_inventory_owner;
 GRANT SELECT ("sessionId",kind) ON public.session_metadata TO lomi_remote_inventory_owner;
 GRANT SELECT ("hostId","accountId","accessEpoch","finalizedIdentity","hostKeyFingerprint") ON public.host_identity TO lomi_remote_inventory_owner;
 GRANT SELECT (id,"hostId","accountId","hostAccessEpoch","approvedAccountEpoch",confirmed,revoked,"clientClass","accessExpiresAt","idleExpiresAt") ON public.host_authorization TO lomi_remote_inventory_owner;
 GRANT SELECT ("hostId","authorizationId","runtimeId",generation,"hostAccessEpoch","leaseExpiresAt","freshUntil","publicationSeq",workspaces) ON public.host_runtime TO lomi_remote_inventory_owner;
 GRANT EXECUTE ON FUNCTION public.lomi_host_runtime_publication_valid(jsonb) TO lomi_remote_inventory_owner;
 GRANT CREATE ON SCHEMA public TO lomi_remote_inventory_owner;
 SELECT pg_get_userbyid(proowner) INTO STRICT owner_name FROM pg_proc WHERE oid=signature::regprocedure;
 IF owner_name NOT IN ('lomi_migrator','lomi_remote_inventory_owner',current_user) THEN RAISE EXCEPTION 'unexpected inventory function owner'; END IF;
 EXECUTE format('ALTER FUNCTION %s OWNER TO lomi_remote_inventory_owner',signature);
 EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange',signature);
 REVOKE CREATE ON SCHEMA public FROM lomi_remote_inventory_owner;
END $inventory_owner$;
GRANT EXECUTE ON FUNCTION public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea) TO lomi_remote_api;

-- Pairing writes have a separate sealed identity, with no parent-token reads.
DO $pairing_owner$
DECLARE r record; table_columns record; signature text; owner_name text; destination text;
BEGIN
 IF NOT current_setting('is_superuser')::boolean THEN RAISE EXCEPTION 'pairing sealing requires operator'; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='lomi_remote_pairing_write_owner') THEN
  CREATE ROLE lomi_remote_pairing_write_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 SELECT * INTO STRICT r FROM pg_roles WHERE rolname='lomi_remote_pairing_write_owner';
 IF r.rolcanlogin OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR
  EXISTS(SELECT FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid) THEN
  RAISE EXCEPTION 'unexpected pairing execution owner'; END IF;
 GRANT USAGE ON SCHEMA public TO lomi_remote_pairing_write_owner;
 REVOKE ALL ON ALL TABLES IN SCHEMA public FROM lomi_remote_pairing_write_owner;
 FOR table_columns IN
  SELECT c.oid::regclass AS relation,string_agg(quote_ident(a.attname),',' ORDER BY a.attnum) AS columns
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid
  WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f') AND a.attnum>0 AND NOT a.attisdropped GROUP BY c.oid
 LOOP
  EXECUTE format('REVOKE ALL (%s) ON TABLE %s FROM lomi_remote_pairing_write_owner',table_columns.columns,table_columns.relation);
 END LOOP;
 GRANT SELECT ("windowIdentityId","consumerAuthorizationId","signedIdentity","identityFingerprint",revoked) ON public.consumer_window_identity TO lomi_remote_pairing_write_owner;
 GRANT SELECT ("hostId","accountId","accessEpoch","finalizedIdentity","hostKeyFingerprint") ON public.host_identity TO lomi_remote_pairing_write_owner;
 GRANT SELECT (id,"hostId","accountId","hostAccessEpoch","approvedAccountEpoch",confirmed,revoked,"clientClass","accessExpiresAt","idleExpiresAt") ON public.host_authorization TO lomi_remote_pairing_write_owner;
 GRANT SELECT ("hostId","authorizationId","runtimeId",generation,"hostAccessEpoch","leaseExpiresAt","freshUntil","publicationSeq",workspaces) ON public.host_runtime TO lomi_remote_pairing_write_owner;
 GRANT SELECT,INSERT ON public.pairing_proposal,public.pairing_decision,public.pairing_grant,public.grant_revocation,public.channel_proposal,public.channel_admission TO lomi_remote_pairing_write_owner;
 GRANT UPDATE ("maximumGrant",expired) ON public.pairing_proposal TO lomi_remote_pairing_write_owner;
 GRANT UPDATE ("expectedContext",expired) ON public.channel_proposal TO lomi_remote_pairing_write_owner;
 GRANT SELECT,INSERT ON public.channel_ticket,public.channel_transport,public.channel_transport_attempt,public.channel_authority_invalidation TO lomi_remote_pairing_write_owner;
 GRANT DELETE ON public.channel_ticket,public.channel_transport_attempt TO lomi_remote_pairing_write_owner;
 GRANT UPDATE ("tokenHash","issuanceNumber","expiresAt","consumedAt",superseded) ON public.channel_ticket TO lomi_remote_pairing_write_owner;
 GRANT UPDATE ("hostAttachedAt","deviceAttachedAt",closed) ON public.channel_transport TO lomi_remote_pairing_write_owner;
 GRANT SELECT (id,epoch,"expiresAt") ON public.remote_relay_owner TO lomi_remote_pairing_write_owner;
 GRANT EXECUTE ON FUNCTION public.lomi_host_runtime_publication_valid(jsonb),public.lomi_pairing_uuid_bytes(uuid),public.lomi_pairing_request_normalize(jsonb) TO lomi_remote_pairing_write_owner;
 GRANT EXECUTE ON FUNCTION public.lomi_pairing_grant_id(jsonb),public.lomi_pairing_grant_valid(public.pairing_proposal,jsonb) TO lomi_remote_pairing_write_owner;
 GRANT EXECUTE ON FUNCTION public.lomi_channel_request_normalize(jsonb),public.lomi_channel_context(uuid,jsonb,jsonb,bigint,bigint),public.lomi_channel_wire_valid(jsonb) TO lomi_remote_pairing_write_owner;
 GRANT CREATE ON SCHEMA public TO lomi_remote_pairing_write_owner,lomi_remote_inventory_owner;
 FOREACH signature IN ARRAY ARRAY[
  'public.lomi_consumer_assertion_recheck(uuid,uuid,text,text,bigint,bigint,boolean,bytea)',
  'public.lomi_consumer_recipient_recheck(uuid,uuid)',
  'public.lomi_pairing_host_current(uuid,bytea,jsonb,boolean)',
  'public.lomi_pairing_retained(uuid)',
  'public.lomi_pairing_pending(uuid,bytea)',
  'public.lomi_pairing_host_prepare(uuid,bytea,jsonb,text,jsonb)',
  'public.lomi_pairing_host_finalize(uuid,bytea,jsonb,text,jsonb,jsonb)',
  'public.lomi_pairing_create_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb)',
  'public.lomi_pairing_peer_host_read(uuid,bytea)',
  'public.lomi_pairing_peer_consumer_read(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid)',
  'public.lomi_grant_revoke_apply(uuid,numeric)',
  'public.lomi_grant_host_revoke(uuid,bytea,numeric)',
  'public.lomi_grant_consumer_revoke(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,numeric)',
  'public.lomi_grant_revocation_commit_guard()',
  'public.lomi_transport_fence(uuid,boolean)',
  'public.lomi_transport_evidence(uuid,boolean)',
  'public.lomi_transport_runtime(uuid,jsonb)',
  'public.lomi_transport_owner_live(text,bigint)',
  'public.lomi_ticket_prepare_apply(uuid,text)',
  'public.lomi_ticket_finalize_apply(uuid,text,bytea)',
  'public.lomi_transport_current(uuid,text,bigint,boolean)',
  'public.lomi_transport_consume_prepare(uuid,bytea,text,bigint)',
  'public.lomi_transport_consume_finalize(uuid,text,bigint)',
  'public.lomi_transport_validate_prepare(uuid,text,bigint)',
  'public.lomi_transport_validate_finalize(uuid,text,bigint)',
  'public.lomi_ticket_host_prepare(uuid,bytea,jsonb)',
  'public.lomi_ticket_host_finalize(uuid,bytea,jsonb,bytea)',
  'public.lomi_ticket_consumer_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,jsonb)',
  'public.lomi_ticket_consumer_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,jsonb,bytea)',
  'public.lomi_transport_draft_commit_guard()',
  'public.lomi_channel_host_auth(uuid,bytea)',
  'public.lomi_channel_consumer_scope(uuid,uuid,uuid,text)',
  'public.lomi_channel_grant_state(uuid,jsonb)',
  'public.lomi_channel_retained(uuid)',
  'public.lomi_channel_draft_commit_guard()',
  'public.lomi_channel_create_apply(text,uuid,jsonb)',
  'public.lomi_channel_finalize_apply(uuid,text,uuid,text)',
  'public.lomi_channel_host_prepare(bytea,jsonb)',
  'public.lomi_channel_consumer_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb)',
  'public.lomi_channel_peer_host_read(uuid,bytea)',
  'public.lomi_channel_host_finalize(uuid,bytea,text)',
  'public.lomi_channel_peer_consumer_read(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid)',
  'public.lomi_channel_consumer_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,text)',
  'public.lomi_channel_pending(uuid,bytea)',
  'public.lomi_channel_admission_prepare(uuid,bytea,jsonb,jsonb)',
  'public.lomi_channel_admission_finalize(uuid,bytea,jsonb,jsonb,jsonb)',
  'public.lomi_pairing_target(uuid,uuid,bigint,bigint,jsonb)',
  'public.lomi_pairing_draft_commit_guard()',
  'public.lomi_pairing_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb)',
  'public.lomi_pairing_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,text)'
 ] LOOP
  destination:=CASE WHEN signature LIKE 'public.lomi_consumer_%' THEN 'lomi_remote_inventory_owner' ELSE 'lomi_remote_pairing_write_owner' END;
  SELECT pg_get_userbyid(proowner) INTO STRICT owner_name FROM pg_proc WHERE oid=signature::regprocedure;
  IF owner_name NOT IN ('lomi_migrator',destination,current_user) THEN RAISE EXCEPTION 'unexpected pairing function owner'; END IF;
  EXECUTE format('ALTER FUNCTION %s OWNER TO %I',signature,destination);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner',signature);
 END LOOP;
 REVOKE CREATE ON SCHEMA public FROM lomi_remote_pairing_write_owner,lomi_remote_inventory_owner;
 GRANT EXECUTE ON FUNCTION public.lomi_consumer_assertion_recheck(uuid,uuid,text,text,bigint,bigint,boolean,bytea) TO lomi_remote_pairing_write_owner;
END $pairing_owner$;
REVOKE ALL ON TABLE public.pairing_proposal FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL (id,"accountId","consumerAuthorizationId","operationId","hostId",request,"trustedGrant",identities,authority,"createdAt","pendingExpiresAt","maximumGrant","creatorTransaction","creatorBackend",expired) ON public.pairing_proposal FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL ON FUNCTION public.lomi_pairing_uuid_bytes(uuid),public.lomi_pairing_request_normalize(jsonb),public.lomi_pairing_proposal_guard() FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
GRANT EXECUTE ON FUNCTION public.lomi_pairing_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,text) TO lomi_remote_api;

-- 008 retires the obsolete creation entrypoint on every grant reapplication.
REVOKE ALL ON FUNCTION public.lomi_pairing_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb) FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange;
GRANT EXECUTE ON FUNCTION public.lomi_pairing_create_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb),public.lomi_pairing_pending(uuid,bytea),
 public.lomi_pairing_host_prepare(uuid,bytea,jsonb,text,jsonb),public.lomi_pairing_host_finalize(uuid,bytea,jsonb,text,jsonb,jsonb) TO lomi_remote_api;
GRANT EXECUTE ON FUNCTION public.lomi_host_access_lookup(uuid,bytea) TO lomi_remote_pairing_write_owner;
REVOKE ALL ON public.pairing_decision,public.pairing_grant FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL ("pairingId",decision,wire,"createdAt") ON public.pairing_decision FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL ("pairingId","grantId","accountId","hostId","hostAuthorizationId","consumerAuthorizationId","accountSessionId","windowIdentityId","runtimeId","runtimeGeneration","workspaceId","workspaceEpoch","hostAccessEpoch","grantRevision","verifiedGrant","signedGrant","expiresAt") ON public.pairing_grant FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL ON FUNCTION public.lomi_pairing_grant_id(jsonb),public.lomi_pairing_grant_valid(public.pairing_proposal,jsonb),public.lomi_pairing_decision_guard(),public.lomi_pairing_grant_guard() FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
GRANT EXECUTE ON FUNCTION public.lomi_consumer_recipient_recheck(uuid,uuid) TO lomi_remote_pairing_write_owner;

-- 009 only exposes peer-scoped wrappers; the revocation overlay remains private.
REVOKE ALL ON public.grant_revocation FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL ("grantId","pairingId","expectedGrantRevision","grantRevision","createdAt") ON public.grant_revocation FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL ON FUNCTION public.lomi_grant_revocation_guard() FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
GRANT EXECUTE ON FUNCTION public.lomi_pairing_peer_host_read(uuid,bytea),public.lomi_pairing_peer_consumer_read(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid),
 public.lomi_grant_host_revoke(uuid,bytea,numeric),public.lomi_grant_consumer_revoke(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,numeric) TO lomi_remote_api;

-- 010 exposes context/admission wrappers only. Channel rows never inherit the
-- legacy remote_channel API privileges or ambient Auth table grants.
REVOKE ALL ON public.channel_proposal,public.channel_admission FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL (id,"grantId","accountId","hostId","hostAuthorizationId","consumerAuthorizationId","creatorKind","creatorAuthorizationId","creatorHostAuthorizationId","creatorConsumerAuthorizationId","operationId",request,context,authority,"expectedContext","issuedAt","expiresAt","creatorTransaction","creatorBackend",expired) ON public.channel_proposal FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL ("channelId",wire,"createdAt") ON public.channel_admission FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL ON FUNCTION public.lomi_channel_request_normalize(jsonb),public.lomi_channel_context(uuid,jsonb,jsonb,bigint,bigint),public.lomi_channel_wire_valid(jsonb),public.lomi_channel_proposal_guard(),public.lomi_channel_admission_guard() FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
GRANT EXECUTE ON FUNCTION public.lomi_channel_host_prepare(bytea,jsonb),public.lomi_channel_consumer_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb),
 public.lomi_channel_host_finalize(uuid,bytea,text),public.lomi_channel_consumer_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,text),
 public.lomi_channel_peer_host_read(uuid,bytea),public.lomi_channel_peer_consumer_read(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid),public.lomi_channel_pending(uuid,bytea),
 public.lomi_channel_admission_prepare(uuid,bytea,jsonb,jsonb),public.lomi_channel_admission_finalize(uuid,bytea,jsonb,jsonb,jsonb) TO lomi_remote_api;

-- 011 tickets/attachments remain disjoint from legacy relay token storage.
REVOKE ALL ON public.channel_ticket,public.channel_transport,public.channel_transport_attempt,public.channel_authority_invalidation FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL (id,"channelId",role,"tokenHash","issuanceNumber","expiresAt","consumedAt",superseded,"creatorTransaction","creatorBackend") ON public.channel_ticket FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL ("channelId","accountId","hostId","ownerId","ownerEpoch","firstAttachedAt","grantExpiresAt","hostAttachedAt","deviceAttachedAt",closed) ON public.channel_transport FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL (id,"channelId",kind,role,"ticketId","ownerId","ownerEpoch",evidence,"creatorTransaction","creatorBackend") ON public.channel_transport_attempt FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL ("channelId","observedAt") ON public.channel_authority_invalidation FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
REVOKE ALL ON FUNCTION public.lomi_transport_fence(uuid,boolean),
 public.lomi_channel_expiry_classify(),
 public.lomi_transport_evidence(uuid,boolean),
 public.lomi_transport_runtime(uuid,jsonb),
 public.lomi_transport_owner_live(text,bigint),
 public.lomi_ticket_prepare_apply(uuid,text),
 public.lomi_ticket_finalize_apply(uuid,text,bytea),
 public.lomi_transport_current(uuid,text,bigint,boolean),
 public.lomi_transport_consume_prepare(uuid,bytea,text,bigint),
 public.lomi_transport_consume_finalize(uuid,text,bigint),
 public.lomi_transport_validate_prepare(uuid,text,bigint),
 public.lomi_transport_validate_finalize(uuid,text,bigint),
 public.lomi_ticket_host_prepare(uuid,bytea,jsonb),
 public.lomi_ticket_host_finalize(uuid,bytea,jsonb,bytea),
 public.lomi_ticket_consumer_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,jsonb),
 public.lomi_ticket_consumer_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,jsonb,bytea),
 public.lomi_transport_write_guard(),
 public.lomi_transport_draft_commit_guard() FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_inventory_owner;
GRANT EXECUTE ON FUNCTION public.lomi_transport_consume_prepare(uuid,bytea,text,bigint),
 public.lomi_transport_consume_finalize(uuid,text,bigint),
 public.lomi_transport_validate_prepare(uuid,text,bigint),
 public.lomi_transport_validate_finalize(uuid,text,bigint),
 public.lomi_ticket_host_prepare(uuid,bytea,jsonb),
 public.lomi_ticket_host_finalize(uuid,bytea,jsonb,bytea),
 public.lomi_ticket_consumer_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,jsonb),
 public.lomi_ticket_consumer_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,jsonb,bytea) TO lomi_remote_api;
