-- Execute as owner after the additive migration; worker login/password is
-- provisioned separately, exactly like the existing runtime roles.
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='lomi_push_worker') THEN CREATE ROLE lomi_push_worker NOLOGIN; END IF; END $$;
GRANT USAGE ON SCHEMA public TO lomi_push_worker;
GRANT SELECT, INSERT, UPDATE ON notification_preference, push_source, push_installation, push_event, push_delivery, push_attempt TO lomi_remote_api;
GRANT SELECT ON push_project_circuit TO lomi_remote_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_preference, push_source, push_installation, push_event, push_delivery, push_attempt, push_project_circuit TO lomi_runtime;
GRANT SELECT ON notification_preference, push_source, push_event TO lomi_push_worker;
GRANT SELECT, UPDATE ON push_delivery TO lomi_push_worker;
GRANT SELECT (id, "userId", "mobileSessionId", environment, "expoProjectId", "appIdentifier", platform, enabled, "retiredAt", "permissionState", "expoTokenCiphertext", "expoTokenHash", "bindingId", "bindingGeneration", "receiveEpoch", "tokenGeneration") ON push_installation TO lomi_push_worker;
GRANT UPDATE (enabled, "receiveEpoch", revision, "disabledReason", "expoTokenCiphertext", "expoTokenHash", "updatedAt") ON push_installation TO lomi_push_worker;
GRANT SELECT, INSERT, UPDATE ON push_attempt, push_project_circuit, "rateLimit" TO lomi_push_worker;
GRANT SELECT (id, status) ON "user" TO lomi_push_worker;
GRANT SELECT (id, "userId", "expiresAt") ON "session" TO lomi_push_worker;
GRANT SELECT ("sessionId", kind) ON session_metadata TO lomi_push_worker;
GRANT SELECT (id, "userId", "sourceSessionId", "authorizationId", "expiresAt", "idleExpiresAt", "revokedAt") ON mobile_session TO lomi_push_worker;
GRANT SELECT (id, "userId", "sourceSessionId", "clientId", version, scope, "expiresAt", "revokedAt") ON remote_service_authorization TO lomi_push_worker;
