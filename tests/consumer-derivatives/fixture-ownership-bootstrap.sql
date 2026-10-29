-- PREPARED ONLY: synthetic fixture ownership bootstrap, exactly once, never production ops.
-- FC66 baseline migrations run as fixture operator. Install candidate as operator;
-- transfer only the named reviewed function objects to intended initial owners.
-- Run before helper sealing. Repeating after sealing is forbidden, not a repair.
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
GRANT CREATE ON SCHEMA public TO lomi_migrator,lomi_remote_inventory_owner,lomi_remote_pairing_write_owner;
ALTER FUNCTION public.lomi_consumer_principal_live_v2(public.consumer_authorization) OWNER TO lomi_migrator;
ALTER FUNCTION public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea) OWNER TO lomi_migrator;
ALTER FUNCTION public.lomi_consumer_assertion_v2_recheck(public.lomi_consumer_assertion_v2) OWNER TO lomi_remote_inventory_owner;
ALTER FUNCTION public.lomi_consumer_require_live(public.consumer_authorization) OWNER TO lomi_migrator;
ALTER FUNCTION public.lomi_consumer_authorization_guard() OWNER TO lomi_migrator;
ALTER FUNCTION public.lomi_derivative_birth_guard_v2() OWNER TO lomi_migrator;
ALTER FUNCTION public.lomi_derivative_consent_guard_v2() OWNER TO lomi_migrator;
ALTER FUNCTION public.lomi_consumer_inventory_v2(public.lomi_consumer_assertion_v2) OWNER TO lomi_remote_pairing_write_owner;
ALTER FUNCTION public.lomi_pairing_create_prepare_v2(public.lomi_consumer_assertion_v2,jsonb) OWNER TO lomi_remote_pairing_write_owner;
ALTER FUNCTION public.lomi_pairing_finalize_v2(public.lomi_consumer_assertion_v2,uuid,text) OWNER TO lomi_remote_pairing_write_owner;
ALTER FUNCTION public.lomi_pairing_peer_consumer_read_v2(public.lomi_consumer_assertion_v2,uuid) OWNER TO lomi_remote_pairing_write_owner;
ALTER FUNCTION public.lomi_grant_consumer_revoke_v2(public.lomi_consumer_assertion_v2,uuid,numeric) OWNER TO lomi_remote_pairing_write_owner;
ALTER FUNCTION public.lomi_channel_consumer_prepare_v2(public.lomi_consumer_assertion_v2,jsonb) OWNER TO lomi_remote_pairing_write_owner;
ALTER FUNCTION public.lomi_channel_peer_consumer_read_v2(public.lomi_consumer_assertion_v2,uuid) OWNER TO lomi_remote_pairing_write_owner;
ALTER FUNCTION public.lomi_channel_consumer_finalize_v2(public.lomi_consumer_assertion_v2,uuid,text) OWNER TO lomi_remote_pairing_write_owner;
ALTER FUNCTION public.lomi_ticket_consumer_prepare_v2(public.lomi_consumer_assertion_v2,uuid,jsonb) OWNER TO lomi_remote_pairing_write_owner;
ALTER FUNCTION public.lomi_ticket_consumer_finalize_v2(public.lomi_consumer_assertion_v2,uuid,jsonb,bytea) OWNER TO lomi_remote_pairing_write_owner;
ALTER FUNCTION public.lomi_approval_source_delete_lock_v2() OWNER TO lomi_migrator;
ALTER FUNCTION public.lomi_approval_source_require_v2(public.consumer_approval_intent,boolean) OWNER TO lomi_migrator;
ALTER FUNCTION public.lomi_approval_consumed_proof_guard_v2() OWNER TO lomi_migrator;
ALTER FUNCTION public.lomi_approval_intent_guard_v2() OWNER TO lomi_migrator;
ALTER FUNCTION public.lomi_approval_flow_guard_v2() OWNER TO lomi_migrator;
ALTER FUNCTION public.lomi_approval_exchange_complete_v2(uuid) OWNER TO lomi_migrator;
ALTER FUNCTION public.lomi_approval_deferred_guard_v2() OWNER TO lomi_migrator;
REVOKE CREATE ON SCHEMA public FROM lomi_migrator,lomi_remote_inventory_owner,lomi_remote_pairing_write_owner;
COMMIT;
