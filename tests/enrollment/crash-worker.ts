import {
  Store,
  Pool,
  type Fault,
} from "../../packages/enrollment-spike/store.ts";
// Synthetic request via stdin, never credentials in argv or output.
const request = await Bun.stdin.json();
const pool = new Pool({
  connectionString: process.env.ENROLLMENT_TEST_URL,
  max: 1,
});
const store = new Store(
  pool,
  Buffer.from(process.env.ENROLLMENT_RECOVERY_KEY!, "hex"),
);
const fault = request.fault as Fault;
let result;
if (request.kind === "exchange")
  result = await store.exchange(request.request, fault);
else
  result = await store.rotate(
    request.family,
    request.token,
    request.operation,
    request.proof,
    fault,
  );
if (fault === "after_receipt") process.exit(73);
// Only a pass marker; credentials are never printed.
if (!result.ok) process.exit(74);
await pool.end();
