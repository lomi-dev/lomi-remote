import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const { chromium } = await import(
  pathToFileURL(
    join(
      root,
      "packages/terminal-renderer/node_modules/@playwright/test/index.mjs",
    ),
  ).href
);
const [wasmDir, nativePath, outputPath] = process.argv.slice(2);
if (!wasmDir || !nativePath || !outputPath)
  throw Error("three explicit fixture paths required");
const limit = 128 * 1024;
const deadline = (promise, ms, label) =>
  new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error(label)), ms);
    Promise.resolve(promise).then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
const native = spawn(nativePath, [], {
  stdio: ["pipe", "pipe", "ignore"],
  env: {},
});
let queue = [],
  buffer = "",
  commands = 0,
  nativeExited = false;
const nativeStatus = { code: null, signal: null, forcedTermination: false };
function rejectPending() {
  for (const q of queue) q.reject(Error("native peer stopped"));
  queue = [];
}
const nativeExit = new Promise((resolve) =>
  native.once("exit", (code, signal) => {
    nativeStatus.code = code;
    nativeStatus.signal = signal;
    nativeExited = true;
    rejectPending();
    resolve();
  }),
);
native.on("error", rejectPending);
native.stdin.on("error", rejectPending);
native.stdout.on("error", rejectPending);
native.stdout.setEncoding("utf8");
native.stdout.on("data", (chunk) => {
  buffer += chunk;
  if (buffer.length > limit) {
    nativeStatus.forcedTermination = true;
    native.kill();
    rejectPending();
    return;
  }
  while (buffer.includes("\n")) {
    const i = buffer.indexOf("\n"),
      line = buffer.slice(0, i);
    buffer = buffer.slice(i + 1);
    const q = queue.shift();
    if (!q) {
      nativeStatus.forcedTermination = true;
      native.kill();
      rejectPending();
      return;
    }
    try {
      q.resolve(JSON.parse(line));
    } catch {
      q.reject(Error("native reply invalid"));
    }
  }
});
async function rpc(command) {
  const encoded = JSON.stringify(command);
  if (encoded.length > limit || ++commands > 200 || nativeExited)
    throw Error("native RPC bound");
  return deadline(
    new Promise((resolve, reject) => {
      queue.push({ resolve, reject });
      native.stdin.write(`${encoded}\n`, (error) => {
        if (error) {
          nativeStatus.forcedTermination = true;
          native.kill();
          rejectPending();
        }
      });
    }),
    5000,
    "native RPC timeout",
  );
}
async function ok(command) {
  const r = await rpc(command);
  if (!Object.hasOwn(r, "ok")) throw Error("native operation rejected");
  return r.ok;
}
const temporary = await mkdtemp(join(tmpdir(), "lomi-v3-chromium-"));
const files = {
  "/crypto.js": ["lomi_remote_crypto.js", "text/javascript"],
  "/lomi_remote_crypto_bg.wasm": [
    "lomi_remote_crypto_bg.wasm",
    "application/wasm",
  ],
};
const server = createServer(async (req, res) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; object-src 'none'; worker-src 'none'",
  );
  try {
    if (req.url === "/") {
      res.setHeader("Content-Type", "text/html");
      res.end("<!doctype html><title>Unqualified v3 crypto fixture</title>");
      return;
    }
    const entry = files[req.url];
    if (!entry) {
      res.writeHead(404);
      res.end();
      return;
    }
    res.setHeader("Content-Type", entry[1]);
    res.end(await readFile(join(wasmDir, entry[0])));
  } catch {
    res.statusCode = 500;
    res.end();
  }
});
let browserServer, browser, closing;
async function cleanup() {
  if (closing) return closing;
  closing = (async () => {
    const failures = [];
    const attempts = [];
    const attempt = async (label, action) => {
      attempts.push(label);
      try {
        await action();
      } catch {
        failures.push(label);
      }
    };
    rejectPending();
    await attempt("native stdin close", async () => native.stdin.end());
    if (!nativeExited) {
      await attempt("native exit", async () => {
        try {
          await deadline(nativeExit, 1000, "native exit timeout");
        } catch {
          nativeStatus.forcedTermination = true;
          native.kill("SIGKILL");
          await deadline(nativeExit, 1000, "native forced exit timeout");
        }
      });
    }
    if (
      !nativeExited ||
      nativeStatus.code !== 0 ||
      nativeStatus.signal !== null ||
      nativeStatus.forcedTermination
    )
      failures.push("native peer did not exit cleanly");
    await attempt("browser close", () =>
      deadline(browser?.close(), 2000, "browser close timeout"),
    );
    if (browserServer) {
      await attempt("browser server close", async () => {
        try {
          await deadline(browserServer.close(), 2000, "server close timeout");
        } catch {
          await attempt("browser server kill", () =>
            deadline(browserServer.kill(), 2000, "server kill timeout"),
          );
          throw Error("browser server required forced cleanup");
        }
      });
    }
    await attempt("HTTP close", async () => {
      server.closeAllConnections();
      await deadline(
        new Promise((resolve) => server.close(resolve)),
        1000,
        "HTTP close timeout",
      );
    });
    await attempt("temporary profile removal", () =>
      deadline(
        rm(temporary, { recursive: true, force: true }),
        2000,
        "profile removal timeout",
      ),
    );
    report.nativeExit = { ...nativeStatus };
    report.cleanupErrors = failures;
    report.cleanupAttempts = attempts;
    if (failures.length) throw Error("proof cleanup failed");
  })();
  return closing;
}
for (const signal of ["SIGINT", "SIGTERM"])
  process.once(signal, () => {
    void cleanup().finally(() => process.exit(130));
  });
const wholeTimer = setTimeout(() => {
  void cleanup().finally(() => process.exit(124));
}, 90000);
let report = {
  scope: "unqualified-v3-native-wasm-browser",
  productionQualified: false,
  passed: false,
};
try {
  const fixtures = await ok({ op: "fixtures" });
  await deadline(
    new Promise((resolve) => server.listen(0, "127.0.0.1", resolve)),
    3000,
    "HTTP listen timeout",
  );
  browserServer = await chromium.launchServer({
    headless: true,
    executablePath: chromium.executablePath(),
    timeout: 15000,
    env: { PATH: "/usr/bin:/bin", HOME: temporary },
    args: ["--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"],
  });
  browser = await chromium.connect(browserServer.wsEndpoint(), {
    timeout: 10000,
  });
  const context = await browser.newContext({
    serviceWorkers: "block",
    permissions: [],
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  await context.route("**/*", (route) => {
    const url = new URL(route.request().url());
    return url.origin === origin ? route.continue() : route.abort();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  await page.goto(origin, { timeout: 10000 });
  await page.exposeFunction("nativeV3", rpc);
  const result = await deadline(
    page.evaluate(async (fixtures) => {
      const m = await import("/crypto.js");
      await m.default();
      let checks = 0;
      const check = (condition, label) => {
        checks++;
        if (!condition) throw Error(label);
      };
      const eq = (a, b) =>
        JSON.stringify(Array.from(a)) === JSON.stringify(Array.from(b));
      const rejects = (fn, label) => {
        let rejected = false;
        try {
          const v = fn();
          v?.free?.();
        } catch {
          rejected = true;
        }
        check(rejected, label);
      };
      const clone = (v) => structuredClone(v);
      const args = (f) => [
        JSON.stringify(f.signed),
        JSON.stringify(f.expected),
        JSON.stringify(f.authority),
        new Uint8Array(f.hostPin),
        new Uint8Array(f.consumerPin),
        100n,
      ];
      const host = m.BrowserIdentity.fixture(true, 7),
        device = m.BrowserIdentity.fixture(false, 17);
      check(
        m.remote_v3_production_qualified() === false,
        "v3 qualification gate",
      );
      check(
        eq(host.fingerprint(), fixtures["a-workspace"].hostPin),
        "host native fingerprint",
      );
      check(
        eq(device.fingerprint(), fixtures["a-workspace"].consumerPin),
        "consumer native fingerprint",
      );
      for (const name of ["a-workspace", "a-terminal"]) {
        const f = fixtures[name];
        const actual = JSON.parse(m.verified_v3_artifacts(...args(f)));
        check(
          actual.grantJson === f.artifacts.grantJson,
          "native/WASM canonical grant JSON",
        );
        check(
          actual.contextJson === f.artifacts.contextJson,
          "native/WASM canonical context JSON",
        );
        for (const field of [
          "grantCbor",
          "contextCbor",
          "grantSignature",
          "contextSignature",
        ])
          check(eq(actual[field], f.artifacts[field]), `native/WASM ${field}`);
      }
      const base = fixtures["a-workspace"],
        terminal = fixtures["a-terminal"];
      const bads = [];
      const changed = (source, edit) => {
        const f = clone(source);
        edit(f);
        bads.push(f);
      };
      changed(base, (f) => (f.hostPin[0] ^= 1));
      changed(base, (f) => (f.consumerPin[0] ^= 1));
      changed(base, (f) => (f.signed.grant.signature[0] ^= 1));
      changed(base, (f) => (f.signed.admission.signature[0] ^= 1));
      changed(base, (f) => (f.signed.host.bundle.identity_key[0] ^= 1));
      changed(base, (f) => (f.signed.consumer.bundle.channel_key[0] ^= 1));
      changed(base, (f) => {
        f.expected.purpose = "terminal";
        f.expected.terminal = clone(terminal.expected.terminal);
        f.authority.terminalMembership = clone(terminal.expected.terminal);
      });
      changed(terminal, (f) => (f.authority.terminalMembership.paneId[0] ^= 1));
      changed(
        terminal,
        (f) => (f.authority.terminalMembership.sessionEpoch[0] ^= 1),
      );
      changed(
        terminal,
        (f) => (f.expected.terminal.terminalProfile = "unknown-profile"),
      );
      changed(base, (f) => (f.authority.accessEpoch = "6"));
      changed(base, (f) => (f.authority.workspaceEpoch[0] ^= 1));
      changed(base, (f) => (f.authority.runtimeGeneration = "14"));
      changed(base, (f) => (f.authority.accountSessionId = "other_session"));
      changed(
        base,
        (f) => (f.signed.grant.grant.capabilities = ["workspace.read"]),
      );
      changed(base, (f) => (f.signed.grant.grant.capabilities = ["unknown"]));
      changed(
        base,
        (f) =>
          (f.signed.grant.grant.capabilities = [
            "workspace.read",
            "terminal.control",
          ]),
      );
      changed(base, (f) => (f.expected.grant.runtimeGeneration = 13));
      changed(base, (f) => (f.authority.accessEpoch = 5));
      changed(base, (f) => (f.authority.accessEpoch = "18446744073709551616"));
      changed(base, (f) => (f.authority.grantRevision = "09"));
      changed(base, (f) => (f.expected.version = 2));
      changed(base, (f) => (f.signed.extra = true));
      changed(base, (f) => (f.expected.extra = true));
      changed(base, (f) => (f.authority.extra = true));
      for (const f of bads)
        rejects(
          () => new m.BrowserHandshakeV3(true, device, ...args(f)),
          "invalid admission rejected before data",
        );
      const expired = args(base);
      expired[5] = 125n;
      rejects(
        () => new m.BrowserHandshakeV3(true, device, ...expired),
        "admission expiry",
      );
      const early = args(base);
      early[5] = 99n;
      rejects(
        () => new m.BrowserHandshakeV3(true, device, ...early),
        "admission not yet valid",
      );
      const numberNow = args(base);
      numberNow[5] = 100;
      rejects(
        () => new m.BrowserHandshakeV3(true, device, ...numberNow),
        "now requires BigInt",
      );
      const overflowNow = args(base);
      overflowNow[5] = (1n << 64n) + 100n;
      rejects(
        () => new m.BrowserHandshakeV3(true, device, ...overflowNow),
        "BigInt overflow rejected without wrapping",
      );
      const negativeNow = args(base);
      negativeNow[5] = -1n;
      rejects(
        () => new m.BrowserHandshakeV3(true, device, ...negativeNow),
        "negative BigInt rejected",
      );
      const large = args(base);
      large[0] = " ".repeat(128 * 1024 + 1);
      rejects(
        () => new m.BrowserHandshakeV3(true, device, ...large),
        "bounded JSON",
      );
      const foreign = m.BrowserIdentity.fixture(false, 27);
      rejects(
        () => new m.BrowserHandshakeV3(true, foreign, ...args(base)),
        "window key mismatch",
      );
      foreign.dispose();
      foreign.free();
      const request = async (command) => {
        const r = await window.nativeV3(command);
        if (!Object.hasOwn(r, "ok"))
          throw Error("native rejected fixture operation");
        return new Uint8Array(r.ok);
      };
      const payload = new TextEncoder().encode("synthetic-v3-界e\u0301");
      async function connect(name, f, identity, initiator, slot) {
        await request({
          op: "start",
          slot,
          case: name,
          side: initiator ? "host" : "consumer",
        });
        const h = new m.BrowserHandshakeV3(initiator, identity, ...args(f));
        if (initiator) {
          await request({ op: "read", slot, bytes: Array.from(h.write()) });
          h.read(await request({ op: "write", slot }));
          await request({ op: "read", slot, bytes: Array.from(h.write()) });
        } else {
          h.read(await request({ op: "write", slot }));
          await request({ op: "read", slot, bytes: Array.from(h.write()) });
          h.read(await request({ op: "write", slot }));
        }
        const c = h.finish();
        check(
          eq(c.transcript_hash(), await request({ op: "finish", slot })),
          "native/WASM XX transcript",
        );
        const route = new Uint8Array(f.expected.channelId);
        const frame = c.seal_binary(route, payload);
        check(
          eq(
            await request({ op: "open", slot, bytes: Array.from(frame) }),
            payload,
          ),
          "WASM to native transport",
        );
        const nativeFrame = await request({
          op: "seal",
          slot,
          bytes: Array.from(payload),
        });
        check(
          eq(c.open_binary(route, nativeFrame), payload),
          "native to WASM transport",
        );
        return { channel: c, frame, nativeFrame, route, slot };
      }
      const active = [];
      for (const name of ["a-workspace", "a-terminal"]) {
        active.push(
          await connect(name, fixtures[name], device, true, `${name}-host`),
        );
        active.push(
          await connect(name, fixtures[name], host, false, `${name}-consumer`),
        );
      }
      await request({
        op: "start",
        slot: "purpose-mismatch",
        case: "a-workspace",
        side: "host",
      });
      const mismatched = new m.BrowserHandshakeV3(
        true,
        device,
        ...args(terminal),
      );
      await request({
        op: "read",
        slot: "purpose-mismatch",
        bytes: Array.from(mismatched.write()),
      });
      const wrongPrologue = await request({
        op: "write",
        slot: "purpose-mismatch",
      });
      rejects(
        () => mismatched.read(wrongPrologue),
        "two valid different purposes cannot finish XX",
      );
      rejects(
        () => mismatched.write(),
        "prologue mismatch fails closed before data",
      );
      mismatched.dispose();
      mismatched.free();
      await request({ op: "dispose", slot: "purpose-mismatch" });
      const b = new m.BrowserIdentity(
        new Uint8Array(16).fill(1),
        new Uint8Array(16).fill(23),
        false,
        1,
      );
      rejects(
        () => new m.BrowserHandshakeV3(true, b, ...args(base)),
        "window B cannot reuse A grant",
      );
      const br = await window.nativeV3({
        op: "window",
        consumer: JSON.parse(b.public_bundle()),
        pin: Array.from(b.fingerprint()),
      });
      check(Object.hasOwn(br, "ok"), "register independent ephemeral window");
      const fb = br.ok;
      check(
        fb.expected.grant.accountSessionId ===
          base.expected.grant.accountSessionId,
        "windows share only BA session",
      );
      check(!eq(fb.consumerPin, base.consumerPin), "window identities differ");
      check(
        !eq(fb.expected.grant.grantId, base.expected.grant.grantId),
        "window grants differ",
      );
      const bc = await connect("b-workspace", fb, b, true, "b-workspace-host");
      active.push(bc);
      const ac = active[0];
      ac.channel.dispose();
      rejects(
        () => ac.channel.seal_binary(ac.route, payload),
        "disposed channel closed",
      );
      check(
        eq(
          await request({
            op: "open",
            slot: bc.slot,
            bytes: Array.from(bc.channel.seal_binary(bc.route, payload)),
          }),
          payload,
        ),
        "closing window A preserves B",
      );
      const replay = active[1];
      check(
        (
          await window.nativeV3({
            op: "open",
            slot: replay.slot,
            bytes: Array.from(replay.frame),
          })
        ).error === true,
        "native replay rejected",
      );
      check(
        (
          await window.nativeV3({
            op: "seal",
            slot: replay.slot,
            bytes: Array.from(payload),
          })
        ).error === true,
        "native replay fails closed",
      );
      const wasmReplay = active[2];
      rejects(
        () =>
          wasmReplay.channel.open_binary(
            wasmReplay.route,
            wasmReplay.nativeFrame,
          ),
        "WASM replay rejected",
      );
      rejects(
        () => wasmReplay.channel.seal_binary(wasmReplay.route, payload),
        "WASM replay fails closed",
      );
      const tamper = active[3];
      const corrupt = await request({
        op: "seal",
        slot: tamper.slot,
        bytes: Array.from(payload),
      });
      corrupt[corrupt.length - 1] ^= 1;
      rejects(
        () => tamper.channel.open_binary(tamper.route, corrupt),
        "WASM tamper rejected",
      );
      rejects(
        () => tamper.channel.seal_binary(tamper.route, payload),
        "WASM tamper closes",
      );
      const abandoned = new m.BrowserHandshakeV3(true, device, ...args(base));
      abandoned.dispose();
      rejects(() => abandoned.write(), "disposed handshake closed");
      abandoned.free();
      const disposed = m.BrowserIdentity.fixture(false, 17);
      disposed.dispose();
      rejects(
        () => new m.BrowserHandshakeV3(true, disposed, ...args(base)),
        "disposed identity rejected",
      );
      disposed.free();
      for (const item of active) {
        item.channel.dispose();
        item.channel.free();
        await request({ op: "dispose", slot: item.slot });
      }
      host.dispose();
      device.dispose();
      b.dispose();
      host.free();
      device.free();
      b.free();
      return {
        checks,
        admissionNegatives: bads.length + 9,
        handshakes: active.length,
        storageUsed: false,
      };
    }, fixtures),
    60000,
    "browser fixture deadline",
  );
  report = {
    ...report,
    ...result,
    passed: true,
    chromiumVersion: browser.version(),
    nativeCommands: commands,
  };
  console.log(
    `v3 Chromium/WASM: ${result.checks} checks, ${result.handshakes} native handshakes passed`,
  );
} finally {
  clearTimeout(wholeTimer);
  try {
    await cleanup();
    report.cleanupCompleted = true;
  } catch (error) {
    report.passed = false;
    report.cleanupCompleted = false;
    throw error;
  } finally {
    await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`);
  }
}
