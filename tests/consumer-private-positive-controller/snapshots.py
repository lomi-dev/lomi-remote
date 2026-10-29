"""Pure fixed-source SQL wrapper construction; never executes SQL or a child."""
import hashlib

CATALOG_SHA = "33fae854e82eaa113e2c8ce156087c57d37b8480f38cd995db5d6f73e2d797ab"
METADATA_SHA = "dde5bcd73f31618392ea10ac7dce83dcd603fdde319b99b104e3b8a9f8ecb732"
SIX_TABLES = ("user", "session", "session_metadata", "remote_account_identity",
              "remote_session_binding", "consumer_authorization")


def fixed_statements(raw, expected, count):
    if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != expected:
        raise RuntimeError("snapshot source rejected")
    # These two exact admitted sources contain SELECT/WITH statements only.
    # Their semicolons terminate lines; comment punctuation is left untouched.
    result = []
    current = []
    for line in raw.decode("utf8", errors="strict").splitlines(keepends=True):
        current.append(line)
        if not line.lstrip().startswith("--") and line.rstrip().endswith(";"):
            text = "".join(current).rstrip()
            result.append(text[:-1])
            current = []
    if any(line.strip() and not line.lstrip().startswith("--") for line in current) or len(result) != count:
        raise RuntimeError("snapshot source rejected")
    return tuple(result)


def snapshot_query(catalog, metadata):
    queries = (*fixed_statements(catalog,CATALOG_SHA,6), *fixed_statements(metadata,METADATA_SHA,10))
    sections = [f"SELECT {index}::smallint AS section,\n"
                " convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE \"C\")::text,'[]'),'UTF8') AS payload\n"
                f"FROM (\n{query}\n) AS fixed_rows(value)" for index,query in enumerate(queries,1)]
    counts = ",\n ".join(f'(SELECT count(*) FROM public."{name}")' for name in SIX_TABLES)
    sections.append("SELECT 17::smallint AS section,\n convert_to(jsonb_build_array(\n "+counts+")::text,'UTF8') AS payload")
    return "\nUNION ALL\n".join(sections)


def private_wrapper(catalog, metadata):
    query = snapshot_query(catalog,metadata)
    return ("""-- Source-only private driver. Never emit raw snapshots or table contents.
-- The unchanged include emits exactly the original thirteen NOTICE markers.
-- TEMP baseline is committed before the included BEGIN and survives ROLLBACK.
SET search_path = pg_catalog, public, pg_temp;
CREATE TEMPORARY VIEW lomi_private_snapshot AS
"""+query+""";
CREATE TEMPORARY TABLE lomi_private_baseline (
 section smallint PRIMARY KEY, payload bytea NOT NULL
) ON COMMIT PRESERVE ROWS;
INSERT INTO pg_temp.lomi_private_baseline SELECT * FROM pg_temp.lomi_private_snapshot;
DO $private_before$
BEGIN
 IF current_user <> 'e2_owner' OR session_user <> 'e2_owner'
  OR (SELECT count(*) FROM pg_temp.lomi_private_baseline) <> 17
  OR (SELECT jsonb_array_length(convert_from(payload,'UTF8')::jsonb)
      FROM pg_temp.lomi_private_baseline WHERE section=1) <> 27
  OR (SELECT convert_from(payload,'UTF8')::jsonb FROM pg_temp.lomi_private_baseline WHERE section=17)
      IS DISTINCT FROM to_jsonb(ARRAY[0::bigint,0,0,0,0,0])
 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='private precondition rejected'; END IF;
END $private_before$;
\\ir positive-auth.sql
DO $private_after$
BEGIN
 IF current_user <> 'e2_owner' OR session_user <> 'e2_owner'
  OR nullif(current_setting('lomi_positive.credential_hash',true),'') IS NOT NULL
  OR EXISTS((SELECT section,payload FROM pg_temp.lomi_private_baseline)
            EXCEPT (SELECT section,payload FROM pg_temp.lomi_private_snapshot))
  OR EXISTS((SELECT section,payload FROM pg_temp.lomi_private_snapshot)
            EXCEPT (SELECT section,payload FROM pg_temp.lomi_private_baseline))
 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='private postcondition rejected'; END IF;
END $private_after$;
DROP VIEW pg_temp.lomi_private_snapshot;
DROP TABLE pg_temp.lomi_private_baseline;
""").encode("utf8")
