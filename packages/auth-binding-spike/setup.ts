import { Kysely, PostgresDialect, sql } from "kysely";
import { Pool } from "pg";
import { getMigrations } from "better-auth/db/migration";
import { options, auth, ORIGIN } from "./auth.ts";
const db = new Kysely<any>({
  dialect: new PostgresDialect({
    pool: new Pool({ connectionString: process.env.AUTH_BINDING_OWNER_URL }),
  }),
});
try {
  await sql`CREATE SCHEMA ba_fixture`.execute(db);
  const migration = await getMigrations(options(db));
  await migration.runMigrations();
  // Schema is owned only by this disposable experiment; no application migration.
  await sql
    .raw(await Bun.file(`${import.meta.dir}/schema.sql`).text())
    .execute(db);
  const checked = await auth(db).handler(new Request(`${ORIGIN}/api/auth/ok`));
  if (checked.status !== 200) throw Error("outer schema validation failed");
} finally {
  await db.destroy();
}
