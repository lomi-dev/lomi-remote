-- The user-row lock is needed for session creation after external OAuth completes.
-- Existing-session expiry UPDATE cannot resurrect a deleted row, and does not need this lock.
DROP TRIGGER IF EXISTS "session_active_user_guard" ON "session";

CREATE TRIGGER "session_active_user_guard"
    BEFORE INSERT ON "session"
    FOR EACH ROW
    EXECUTE FUNCTION "lomi_require_active_session_user"();
