-- Disposable E0 store experiment. No production migration or platform roles.
CREATE SCHEMA enrollment_spike;
SET search_path TO enrollment_spike;
CREATE TABLE account (
  id uuid PRIMARY KEY, state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','suspended')),
  access_epoch bigint NOT NULL DEFAULT 1 CHECK(access_epoch > 0)
);
CREATE TABLE enrollment (
  id uuid PRIMARY KEY, account_id uuid NOT NULL REFERENCES account,
  access_epoch bigint NOT NULL CHECK(access_epoch > 0),
  host_id uuid NOT NULL, host_fingerprint bytea NOT NULL CHECK(octet_length(host_fingerprint)=32),
  bootstrap_session_id uuid NOT NULL UNIQUE,
  client_class text NOT NULL CHECK (client_class='host-enrollment'),
  expected jsonb NOT NULL, approved boolean NOT NULL CHECK(approved),
  consumed_operation uuid, UNIQUE(id,account_id)
);
CREATE FUNCTION immutable_enrollment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.id,NEW.account_id,NEW.host_id,NEW.host_fingerprint,NEW.bootstrap_session_id,
      NEW.client_class,NEW.expected,NEW.approved,NEW.access_epoch)
     IS DISTINCT FROM
     (OLD.id,OLD.account_id,OLD.host_id,OLD.host_fingerprint,OLD.bootstrap_session_id,
      OLD.client_class,OLD.expected,OLD.approved,OLD.access_epoch) THEN
    RAISE EXCEPTION 'immutable enrollment binding';
  END IF;
  IF OLD.consumed_operation IS NOT NULL AND NEW.consumed_operation IS DISTINCT FROM OLD.consumed_operation THEN
    RAISE EXCEPTION 'consumed enrollment';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER immutable_enrollment BEFORE UPDATE ON enrollment
FOR EACH ROW EXECUTE FUNCTION immutable_enrollment();
CREATE TABLE family (
  id uuid PRIMARY KEY, enrollment_id uuid NOT NULL UNIQUE REFERENCES enrollment,
  account_id uuid NOT NULL REFERENCES account, access_epoch bigint NOT NULL,
  revoked boolean NOT NULL DEFAULT false, confirmed boolean NOT NULL DEFAULT false, rotation integer NOT NULL DEFAULT 0,
  access_hash bytea NOT NULL, access_expires_at timestamptz NOT NULL,
  FOREIGN KEY(enrollment_id,account_id) REFERENCES enrollment(id,account_id)
);
CREATE FUNCTION immutable_family() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.id,NEW.enrollment_id,NEW.account_id,NEW.access_epoch) IS DISTINCT FROM
     (OLD.id,OLD.enrollment_id,OLD.account_id,OLD.access_epoch)
     OR (OLD.revoked AND NOT NEW.revoked) THEN RAISE EXCEPTION 'immutable family'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER immutable_family BEFORE UPDATE ON family
FOR EACH ROW EXECUTE FUNCTION immutable_family();
CREATE TABLE credential (
  hash bytea PRIMARY KEY CHECK(octet_length(hash)=32), family_id uuid NOT NULL REFERENCES family,
  rotation integer NOT NULL, consumed_operation uuid, expires_at timestamptz NOT NULL,
  UNIQUE(family_id,rotation)
);
CREATE TABLE recovery (
  kind text NOT NULL CHECK(kind IN ('exchange','rotate')), subject_id uuid NOT NULL,
  operation_id uuid NOT NULL, account_id uuid NOT NULL REFERENCES account,
  credential_hash bytea, expected jsonb NOT NULL,
  sealed bytea CHECK(octet_length(sealed)<=4096), expires_at timestamptz NOT NULL,
  UNIQUE(kind,subject_id),
  PRIMARY KEY(kind,subject_id,operation_id)
);
REVOKE ALL ON SCHEMA enrollment_spike FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA enrollment_spike FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA enrollment_spike FROM PUBLIC;
