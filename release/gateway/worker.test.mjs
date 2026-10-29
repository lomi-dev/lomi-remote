import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { createReleaseWorker, GatewayError, verifyReleaseEnvelope } from "./worker.mjs";

const NOW = Date.parse("2026-10-29T12:00:00Z");
const REPOSITORY = "lomi-dev/lomi-remote";
const KEY_PAIR = await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const PUBLIC_KEY = new Uint8Array(await webcrypto.subtle.exportKey("raw", KEY_PAIR.publicKey));
const PUBLIC_KEY_BASE64 = Buffer.from(PUBLIC_KEY).toString("base64");

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function defaultAssetData(version) {
  return {
    "install.sh": new TextEncoder().encode(`#!/bin/sh\nprintf '%s\\n' '${version}'\n`),
    "install.ps1": new TextEncoder().encode(`Write-Output '${version}'\n`),
    "metadata/timestamp.json": new TextEncoder().encode(`timestamp-${version}`),
    "metadata/snapshot.json": new TextEncoder().encode(`snapshot-${version}`),
    "metadata/targets.json": new TextEncoder().encode(`targets-${version}`),
    "metadata/1.root.json": new TextEncoder().encode(`root-${version}`),
    "targets/linux/x86_64/lomiremote": new TextEncoder().encode(`target-${version}`),
    [`lomi-remote-linux-x86_64-${version}.zip`]: new TextEncoder().encode(`archive-${version}`),
  };
}

async function makeRelease({
  version = "0.1.0",
  repository = REPOSITORY,
  issuedAt = new Date(NOW - 60_000).toISOString().replace(".000Z", "Z"),
  expiresAt = new Date(NOW + 2 * 24 * 60 * 60_000).toISOString().replace(".000Z", "Z"),
  data = defaultAssetData(version),
  extraFiles = {},
} = {}) {
  const files = {};
  const assets = new Map();
  for (const [logicalPath, bytes] of Object.entries({ ...data, ...extraFiles })) {
    const value = bytes instanceof Uint8Array ? bytes : new TextEncoder().encode(bytes);
    const digest = hex(await webcrypto.subtle.digest("SHA-256", value));
    let asset;
    if (logicalPath === "install.sh" || logicalPath === "install.ps1") asset = logicalPath;
    else if (logicalPath === "metadata/timestamp.json") asset = `tuf-timestamp-${version}-${digest.slice(0, 16)}.json`;
    else if (logicalPath === "metadata/snapshot.json") asset = `tuf-snapshot-${version}-${digest.slice(0, 16)}.json`;
    else if (logicalPath === "metadata/targets.json") asset = `tuf-targets-${version}-${digest.slice(0, 16)}.json`;
    else if (logicalPath === "metadata/1.root.json") asset = `tuf-1-root-${version}-${digest.slice(0, 16)}.json`;
    else if (logicalPath === "targets/linux/x86_64/lomiremote") asset = "target-linux-x86_64-lomiremote";
    else asset = logicalPath.split("/").at(-1);
    files[logicalPath] = { asset, size: value.byteLength, sha256: digest };
    assets.set(asset, value);
  }
  const index = {
    format: 1,
    repository,
    tag: `v${version}`,
    version,
    issuedAt,
    expiresAt,
    platforms: ["linux-x86_64"],
    files,
  };
  const signedBytes = new TextEncoder().encode(canonicalize(index));
  const signatureBytes = new Uint8Array(await webcrypto.subtle.sign("Ed25519", KEY_PAIR.privateKey, signedBytes));
  const envelope = { signed: index, signature: Buffer.from(signatureBytes).toString("base64") };
  const envelopeBytes = new TextEncoder().encode(canonicalize(envelope));
  return { index, envelope, signedBytes, signatureBytes, envelopeBytes, assets };
}

function responseForBytes(bytes, status = 200) {
  return new Response(bytes, {
    status,
    headers: { "Content-Length": String(bytes.byteLength) },
  });
}

function makeHarness({
  latest,
  versions = new Map(),
  recoveryLatest,
  recoveryVersions = new Map(),
  missingLatestPrimary = false,
  missingVersionPrimary = new Set(),
  clock = { value: NOW },
  cache = null,
  redirectLatest = null,
  fixedLengthStreamImpl,
  assetResponseFactory = null,
} = {}) {
  const calls = [];
  const assetVersions = new Map(versions);
  const fetchImpl = async (input, init) => {
    const url = new URL(input);
    calls.push({ url: url.href, init });
    assert.equal(init.redirect, "manual");
    assert.equal(init.credentials, "omit");
    if (url.hostname !== "github.com") return new Response("cdn unexpected", { status: 404 });
    if (url.pathname === `/${REPOSITORY}/releases/latest/download/release-index.json`) {
      if (redirectLatest) return new Response(null, { status: 302, headers: { Location: redirectLatest } });
      if (missingLatestPrimary) return new Response("not found", { status: 404 });
      return latest ? responseForBytes(latest.envelopeBytes) : new Response("<html>missing</html>", { status: 404 });
    }
    if (url.pathname === `/${REPOSITORY}/releases/latest/download/release-index-recovery.json`) {
      if (redirectLatest) return new Response(null, { status: 302, headers: { Location: redirectLatest } });
      const recovery = recoveryLatest === undefined ? latest : recoveryLatest;
      return recovery ? responseForBytes(recovery.envelopeBytes) : new Response("not found", { status: 404 });
    }
    const indexMatch = url.pathname.match(new RegExp(`^/${REPOSITORY}/releases/download/(v[^/]+)/release-index\\.json$`));
    if (indexMatch) {
      if (missingVersionPrimary.has(indexMatch[1])) return new Response("not found", { status: 404 });
      const release = versions.get(indexMatch[1]);
      return release ? responseForBytes(release.envelopeBytes) : new Response("not found", { status: 404 });
    }
    const recoveryMatch = url.pathname.match(new RegExp(`^/${REPOSITORY}/releases/download/(v[^/]+)/release-index-recovery\\.json$`));
    if (recoveryMatch) {
      const tag = recoveryMatch[1];
      const recovery = recoveryVersions.has(tag) ? recoveryVersions.get(tag) : versions.get(tag);
      return recovery ? responseForBytes(recovery.envelopeBytes) : new Response("not found", { status: 404 });
    }
    const assetMatch = url.pathname.match(new RegExp(`^/${REPOSITORY}/releases/download/(v[^/]+)/([A-Za-z0-9._-]+)$`));
    if (assetMatch) {
      const release = assetVersions.get(assetMatch[1]) ?? latest;
      const bytes = release?.assets.get(assetMatch[2]);
      if (!bytes) return new Response("not found", { status: 404 });
      return assetResponseFactory ? assetResponseFactory(bytes) : responseForBytes(bytes);
    }
    return new Response("not found", { status: 404 });
  };
  const worker = createReleaseWorker({ fetchImpl, cryptoImpl: webcrypto, cache, now: () => clock.value, fixedLengthStreamImpl });
  const env = { REPOSITORY, RELEASE_INDEX_PUBLIC_KEY: PUBLIC_KEY_BASE64 };
  return {
    worker,
    env,
    calls,
    clock,
    setLatest(next) { latest = next; },
    setVersion(tag, release) {
      if (release) assetVersions.set(tag, release);
      versions.set(tag, release);
    },
  };
}

async function request(worker, env, path, method = "GET") {
  return worker(new Request(`https://lomi.test${path}`, { method }), env);
}

test("verifies exact signed bytes and rejects tampering, expiry, and foreign repositories", async () => {
  const release = await makeRelease();
  const valid = await verifyReleaseEnvelope(release.envelopeBytes, {
    publicKey: PUBLIC_KEY,
    repository: REPOSITORY,
    nowMs: NOW,
    cryptoImpl: webcrypto,
  });
  assert.equal(valid.tag, "v0.1.0");

  const tampered = new TextEncoder().encode(new TextDecoder().decode(release.envelopeBytes).replaceAll("0.1.0", "0.1.1"));
  await assert.rejects(
    verifyReleaseEnvelope(tampered, { publicKey: PUBLIC_KEY, repository: REPOSITORY, nowMs: NOW, cryptoImpl: webcrypto }),
    (error) => error instanceof GatewayError && error.status === 502,
  );

  const expired = await makeRelease({ expiresAt: "2026-10-29T11:59:59Z" });
  await assert.rejects(
    verifyReleaseEnvelope(expired.envelopeBytes, { publicKey: PUBLIC_KEY, repository: REPOSITORY, nowMs: NOW, cryptoImpl: webcrypto }),
    (error) => error instanceof GatewayError && error.status === 502,
  );

  const foreign = await makeRelease({ repository: "attacker/other" });
  await assert.rejects(
    verifyReleaseEnvelope(foreign.envelopeBytes, { publicKey: PUBLIC_KEY, repository: REPOSITORY, nowMs: NOW, cryptoImpl: webcrypto }),
    (error) => error instanceof GatewayError && error.status === 502,
  );
});

test("rejects duplicate JSON keys through canonical-byte enforcement", async () => {
  const bytes = new TextEncoder().encode('{"signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","signed":{}}');
  await assert.rejects(
    verifyReleaseEnvelope(bytes, { publicKey: PUBLIC_KEY, repository: REPOSITORY, nowMs: NOW, cryptoImpl: webcrypto }),
    (error) => error instanceof GatewayError && error.status === 502,
  );
});

test("returns a valid fail-closed shell installer before a release exists", async () => {
  const { worker, env } = makeHarness();
  const shell = await request(worker, env, "/remote/install.sh");
  assert.equal(shell.status, 503);
  const shellBody = await shell.text();
  assert.match(shellBody, /^#!\/bin\/sh\n/);
  assert.match(shellBody, /exit 1/);
  assert.equal(shell.headers.get("Content-Type"), "text/plain;charset=utf-8");
  assert.equal(shell.headers.get("Cache-Control"), "no-store");

  const powershell = await request(worker, env, "/remote/install.ps1");
  assert.equal(powershell.status, 503);
  const powershellBody = await powershell.text();
  assert.match(powershellBody, /\[Console\]::Error/);
  assert.match(powershellBody, /exit 1/);
  assert.doesNotMatch(powershellBody, /<html>/i);
});

test("uses the same-tag recovery envelope when the primary latest envelope is missing", async () => {
  const release = await makeRelease();
  const harness = makeHarness({ latest: release, recoveryLatest: release, missingLatestPrimary: true });
  const installer = await request(harness.worker, harness.env, "/remote/install.sh");
  assert.equal(installer.status, 200);
  assert.match(await installer.text(), /0\.1\.0/);
  assert.deepEqual(harness.calls.slice(0, 2).map(({ url }) => new URL(url).pathname), [
    `/${REPOSITORY}/releases/latest/download/release-index.json`,
    `/${REPOSITORY}/releases/latest/download/release-index-recovery.json`,
  ]);
});

test("uses the recovery envelope when the primary latest signature is invalid", async () => {
  const release = await makeRelease();
  const primary = { ...release, envelope: { ...release.envelope }, signatureBytes: Uint8Array.from(release.signatureBytes) };
  primary.signatureBytes[0] ^= 0xff;
  primary.envelope.signature = Buffer.from(primary.signatureBytes).toString("base64");
  primary.envelopeBytes = new TextEncoder().encode(canonicalize(primary.envelope));
  const harness = makeHarness({ latest: primary, recoveryLatest: release });
  const installer = await request(harness.worker, harness.env, "/remote/install.ps1");
  assert.equal(installer.status, 200);
  assert.match(await installer.text(), /0\.1\.0/);
  assert.deepEqual(harness.calls.slice(0, 2).map(({ url }) => new URL(url).pathname), [
    `/${REPOSITORY}/releases/latest/download/release-index.json`,
    `/${REPOSITORY}/releases/latest/download/release-index-recovery.json`,
  ]);
});

test("fails closed when both primary and recovery envelopes fail signature validation", async () => {
  const invalid = await makeRelease();
  invalid.signatureBytes[0] ^= 0xff;
  invalid.envelope.signature = Buffer.from(invalid.signatureBytes).toString("base64");
  invalid.envelopeBytes = new TextEncoder().encode(canonicalize(invalid.envelope));
  const harness = makeHarness({ latest: invalid, recoveryLatest: invalid });
  const response = await request(harness.worker, harness.env, "/remote/install.ps1");
  assert.equal(response.status, 503);
  const body = await response.text();
  assert.match(body, /\[Console\]::Error/);
  assert.match(body, /exit 1/);
  assert.doesNotMatch(body, /<html>/i);
  assert.equal(harness.calls.length, 2);
});

test("uses the same-tag recovery envelope when an explicit-version primary is missing", async () => {
  const release = await makeRelease({ version: "0.1.0" });
  const tag = release.index.tag;
  const harness = makeHarness({
    latest: release,
    versions: new Map([[tag, release]]),
    recoveryVersions: new Map([[tag, release]]),
    missingVersionPrimary: new Set([tag]),
  });
  const response = await request(harness.worker, harness.env, `/remote/releases/${tag}/targets/linux/x86_64/lomiremote`);
  assert.equal(await response.text(), "target-0.1.0");
  assert.deepEqual(harness.calls.slice(0, 2).map(({ url }) => new URL(url).pathname), [
    `/${REPOSITORY}/releases/download/${tag}/release-index.json`,
    `/${REPOSITORY}/releases/download/${tag}/release-index-recovery.json`,
  ]);
});

test("rejects redirect escape and encoded traversal without fetching outside GitHub", async () => {
  const release = await makeRelease();
  const redirectHarness = makeHarness({
    latest: release,
    versions: new Map([[release.index.tag, release]]),
    redirectLatest: "https://evil.example/lomi-dev/lomi-remote/releases/latest/download/release-index.json",
  });
  const redirected = await request(redirectHarness.worker, redirectHarness.env, "/remote/install.sh");
  assert.equal(redirected.status, 503);
  assert.equal(redirectHarness.calls.length, 2);
  assert.ok(redirectHarness.calls.every(({ url }) => new URL(url).hostname === "github.com"));

  const portHarness = makeHarness({
    latest: release,
    versions: new Map([[release.index.tag, release]]),
    redirectLatest: `https://github.com:443/${REPOSITORY}/releases/latest/download/release-index.json`,
  });
  const portRedirect = await request(portHarness.worker, portHarness.env, "/remote/install.sh");
  assert.equal(portRedirect.status, 503);
  assert.equal(portHarness.calls.length, 2);

  const traversalHarness = makeHarness({ latest: release, versions: new Map([[release.index.tag, release]]) });
  const traversal = await request(traversalHarness.worker, traversalHarness.env, "/remote/releases/%2e%2e/secret");
  assert.equal(traversal.status, 404);
  assert.equal(traversalHarness.calls.length, 0);
});

test("validates current and immutable releases and returns 404 for absent TUF root rotation metadata", async () => {
  const oldRelease = await makeRelease({ version: "0.1.0" });
  const currentRelease = await makeRelease({ version: "0.2.0" });
  const versions = new Map([[oldRelease.index.tag, oldRelease], [currentRelease.index.tag, currentRelease]]);
  const harness = makeHarness({ latest: currentRelease, versions });

  const current = await request(harness.worker, harness.env, "/remote/releases/targets/linux/x86_64/lomiremote");
  assert.equal(current.status, 200);
  assert.equal(await current.text(), "target-0.2.0");

  const currentEnvelope = await request(harness.worker, harness.env, "/remote/releases/release-index.json");
  assert.deepEqual(await currentEnvelope.json(), currentRelease.envelope);

  const latest = await request(harness.worker, harness.env, "/remote/releases/latest.json");
  assert.equal(latest.status, 200);
  const latestBody = await latest.json();
  assert.deepEqual(latestBody, {
    version: "0.2.0",
    tag: "v0.2.0",
    platforms: ["linux-x86_64"],
    releaseUrl: "https://github.com/lomi-dev/lomi-remote/releases/tag/v0.2.0",
  });
  const latestHead = await request(harness.worker, harness.env, "/remote/releases/latest.json", "HEAD");
  assert.equal(latestHead.status, 200);
  assert.equal(latestHead.headers.get("Content-Length"), String(new TextEncoder().encode(JSON.stringify(latestBody)).byteLength));
  assert.equal(await latestHead.text(), "");

  const immutable = await request(harness.worker, harness.env, "/remote/releases/v0.1.0/targets/linux/x86_64/lomiremote");
  assert.equal(immutable.status, 200);
  assert.equal(await immutable.text(), "target-0.1.0");
  const immutableMetadata = await request(harness.worker, harness.env, "/remote/releases/v0.1.0/metadata/targets.json");
  assert.equal(immutableMetadata.status, 200);
  assert.equal(await immutableMetadata.text(), "targets-0.1.0");
  assert.ok(harness.calls.some(({ url }) => url.endsWith(`/releases/download/v0.1.0/${oldRelease.index.files["metadata/targets.json"].asset}`)));

  const missingRoot = await request(harness.worker, harness.env, "/remote/releases/metadata/2.root.json");
  assert.equal(missingRoot.status, 404);
  assert.equal(await missingRoot.text(), "Not found.\n");
  assert.ok(harness.calls.every(({ url }) => new URL(url).hostname === "github.com"));
  assert.ok(harness.calls.every(({ url }) => !url.endsWith("release-index.sig")));
});

test("checks installer and metadata hashes and exact declared sizes", async () => {
  const release = await makeRelease();
  const harness = makeHarness({ latest: release, versions: new Map([[release.index.tag, release]]) });
  const validInstaller = await request(harness.worker, harness.env, "/remote/install.sh");
  assert.equal(validInstaller.status, 200);
  assert.match(await validInstaller.text(), /0\.1\.0/);

  const timestampAsset = release.index.files["metadata/timestamp.json"].asset;
  const originalAsset = release.assets.get(timestampAsset);
  release.assets.set(timestampAsset, new TextEncoder().encode("x".repeat(originalAsset.byteLength)));
  const badHash = await request(harness.worker, harness.env, "/remote/releases/metadata/timestamp.json");
  assert.equal(badHash.status, 502);
  assert.match(await badHash.text(), /digest check/);

  release.assets.set(timestampAsset, originalAsset);
  const mismatchedLengthAsset = release.assets.get("install.sh");
  release.assets.set("install.sh", new TextEncoder().encode("too long for index"));
  const badSize = await request(harness.worker, harness.env, "/remote/install.sh");
  assert.equal(badSize.status, 503);
  assert.match(await badSize.text(), /no authenticated release/);
  release.assets.set("install.sh", mismatchedLengthAsset);
});

test("streams large assets with the signed exact size and supports HEAD without asset fetch", async () => {
  const large = new Uint8Array(1024 * 1024 + 7).fill(0x5a);
  const release = await makeRelease({ extraFiles: { "targets/linux/x86_64/large-target": large } });
  const harness = makeHarness({ latest: release, versions: new Map([[release.index.tag, release]]) });

  const head = await request(harness.worker, harness.env, "/remote/releases/targets/linux/x86_64/large-target", "HEAD");
  assert.equal(head.status, 200);
  assert.equal(head.headers.get("Content-Length"), String(large.byteLength));
  assert.equal(await head.text(), "");
  assert.equal(harness.calls.some(({ url }) => url.endsWith("large-target")), false);

  const downloaded = await request(harness.worker, harness.env, "/remote/releases/targets/linux/x86_64/large-target");
  assert.equal(downloaded.status, 200);
  assert.equal(downloaded.headers.get("Content-Length"), String(large.byteLength));
  assert.equal((await downloaded.arrayBuffer()).byteLength, large.byteLength);
});

test("uses injected FixedLengthStream for large assets and handles pipe rejection", async () => {
  const large = new Uint8Array(1024 * 1024 + 31).fill(0x6b);
  const release = await makeRelease({ extraFiles: { "targets/linux/x86_64/fixed-target": large } });
  const sizes = [];
  class MockFixedLengthStream {
    constructor(size) {
      sizes.push(size);
      const transform = new TransformStream();
      this.readable = transform.readable;
      this.writable = transform.writable;
    }
  }
  const harness = makeHarness({
    latest: release,
    versions: new Map([[release.index.tag, release]]),
    fixedLengthStreamImpl: MockFixedLengthStream,
  });
  const response = await request(harness.worker, harness.env, "/remote/releases/targets/linux/x86_64/fixed-target");
  assert.equal(response.status, 200);
  assert.deepEqual(sizes, [large.byteLength]);
  assert.equal(response.headers.get("Content-Length"), String(large.byteLength));
  assert.equal((await response.arrayBuffer()).byteLength, large.byteLength);

  let rejectionHandled = false;
  const harnessWithRejectedPipe = makeHarness({
    latest: release,
    versions: new Map([[release.index.tag, release]]),
    fixedLengthStreamImpl: MockFixedLengthStream,
    assetResponseFactory(bytes) {
      const source = new ReadableStream({
        start(controller) {
          controller.enqueue(bytes);
          controller.close();
        },
      });
      const rejected = Promise.reject(new Error("mock pipe failure"));
      const nativeCatch = rejected.catch.bind(rejected);
      rejected.catch = (handler) => {
        rejectionHandled = true;
        return nativeCatch(handler);
      };
      source.pipeTo = () => rejected;
      return {
        status: 200,
        headers: new Headers({ "Content-Length": String(bytes.byteLength) }),
        body: source,
      };
    },
  });
  const rejectedResponse = await request(
    harnessWithRejectedPipe.worker,
    harnessWithRejectedPipe.env,
    "/remote/releases/targets/linux/x86_64/fixed-target",
  );
  assert.equal(rejectedResponse.status, 200);
  assert.equal(rejectionHandled, true);
  await Promise.resolve();
});

test("caches only verified latest indexes for sixty seconds and keys cache by repository and key", async () => {
  const first = await makeRelease({ version: "0.1.0" });
  const second = await makeRelease({ version: "0.2.0" });
  const backing = new Map();
  const cache = {
    async match(key) { const value = backing.get(String(key)); return value ? value.clone() : undefined; },
    async put(key, value) { backing.set(String(key), value.clone()); },
    async delete(key) { backing.delete(String(key)); },
  };
  const harness = makeHarness({ latest: first, versions: new Map([[first.index.tag, first], [second.index.tag, second]]), cache });

  const initial = await request(harness.worker, harness.env, "/remote/releases/targets/linux/x86_64/lomiremote");
  assert.equal(await initial.text(), "target-0.1.0");
  const callsAfterInitial = harness.calls.length;
  assert.equal(backing.size, 2);
  const cacheEntry = [...backing.values()].find((entry) => entry.headers.get("Cache-Control") === "public, max-age=60");
  assert.ok(cacheEntry);
  assert.match(cacheEntry.headers.get("Cache-Control"), /max-age=60/);
  harness.setLatest(second);
  const cached = await request(harness.worker, harness.env, "/remote/releases/targets/linux/x86_64/lomiremote");
  assert.equal(await cached.text(), "target-0.1.0");
  assert.equal(harness.calls.length, callsAfterInitial + 1); // latest asset itself is still fetched

  harness.clock.value += 60_001;
  const refreshed = await request(harness.worker, harness.env, "/remote/releases/targets/linux/x86_64/lomiremote");
  assert.equal(await refreshed.text(), "target-0.2.0");
  assert.equal(backing.size, 2);
});

test("does not cache an index until its signature has verified", async () => {
  const invalid = await makeRelease();
  invalid.signatureBytes[0] ^= 0xff;
  invalid.envelope.signature = Buffer.from(invalid.signatureBytes).toString("base64");
  invalid.envelopeBytes = new TextEncoder().encode(canonicalize(invalid.envelope));
  const backing = new Map();
  const cache = {
    async match(key) { return backing.get(String(key))?.clone(); },
    async put(key, value) { backing.set(String(key), value.clone()); },
    async delete(key) { backing.delete(String(key)); },
  };
  const harness = makeHarness({ latest: invalid, versions: new Map([[invalid.index.tag, invalid]]), cache });
  const result = await request(harness.worker, harness.env, "/remote/releases/metadata/timestamp.json");
  assert.equal(result.status, 502);
  assert.equal(backing.size, 0);
});

test("uses verified immutable-envelope cache and versioned metadata asset names", async () => {
  const oldRelease = await makeRelease({ version: "0.1.0" });
  const currentRelease = await makeRelease({ version: "0.2.0" });
  const versions = new Map([[oldRelease.index.tag, oldRelease], [currentRelease.index.tag, currentRelease]]);
  const backing = new Map();
  const cache = {
    async match(key) { return backing.get(String(key))?.clone(); },
    async put(key, value) { backing.set(String(key), value.clone()); },
    async delete(key) { backing.delete(String(key)); },
  };
  const harness = makeHarness({ latest: currentRelease, versions, cache });
  const oldPath = "/remote/releases/v0.1.0/metadata/targets.json";
  const first = await request(harness.worker, harness.env, oldPath);
  assert.equal(await first.text(), "targets-0.1.0");
  const oldIndexFetches = harness.calls.filter(({ url }) => url.endsWith("/releases/download/v0.1.0/release-index.json")).length;
  assert.equal(oldIndexFetches, 1);

  const second = await request(harness.worker, harness.env, oldPath);
  assert.equal(await second.text(), "targets-0.1.0");
  assert.equal(harness.calls.filter(({ url }) => url.endsWith("/releases/download/v0.1.0/release-index.json")).length, 1);
  assert.ok(harness.calls.some(({ url }) => url.endsWith(`/releases/download/v0.1.0/${oldRelease.index.files["metadata/targets.json"].asset}`)));
  assert.ok(!harness.calls.some(({ url }) => url.endsWith("release-index.sig")));
});

test("refreshes explicit-tag metadata envelopes after sixty seconds", async () => {
  const tag = "v0.1.0";
  const original = await makeRelease({ version: "0.1.0" });
  const refreshedData = defaultAssetData("0.1.0");
  refreshedData["metadata/targets.json"] = new TextEncoder().encode("targets-0.1.0-refresh");
  const refreshed = await makeRelease({ version: "0.1.0", data: refreshedData });
  assert.notEqual(
    original.index.files["metadata/targets.json"].asset,
    refreshed.index.files["metadata/targets.json"].asset,
  );

  const clock = { value: NOW };
  const versions = new Map([[tag, original]]);
  const backing = new Map();
  const cache = {
    async match(key) { return backing.get(String(key))?.clone(); },
    async put(key, value) { backing.set(String(key), value.clone()); },
    async delete(key) { backing.delete(String(key)); },
  };
  const harness = makeHarness({ latest: original, versions, clock, cache });
  const path = "/remote/releases/v0.1.0/metadata/targets.json";
  const first = await request(harness.worker, harness.env, path);
  assert.equal(await first.text(), "targets-0.1.0");
  const cachedEnvelope = [...backing.values()][0];
  assert.equal(cachedEnvelope.headers.get("Cache-Control"), "public, max-age=60");

  clock.value += 60_001;
  harness.setVersion(tag, refreshed);
  const second = await request(harness.worker, harness.env, path);
  assert.equal(await second.text(), "targets-0.1.0-refresh");
  assert.equal(harness.calls.filter(({ url }) => url.endsWith(`/releases/download/${tag}/release-index.json`)).length, 2);
  assert.ok(harness.calls.some(({ url }) => url.endsWith(`/releases/download/${tag}/${refreshed.index.files["metadata/targets.json"].asset}`)));

  clock.value += 60_001;
  harness.setVersion(tag, null);
  const duringTagRewrite = await request(harness.worker, harness.env, path);
  assert.equal(duringTagRewrite.status, 200);
  assert.equal(await duringTagRewrite.text(), "targets-0.1.0-refresh");

  clock.value = Date.parse(refreshed.index.expiresAt);
  const afterSignedExpiry = await request(harness.worker, harness.env, path);
  assert.equal(afterSignedExpiry.status, 404);
});

test("falls back to a previously verified latest envelope only within signed expiry", async () => {
  const release = await makeRelease({ expiresAt: "2026-11-01T12:00:00Z" });
  const clock = { value: NOW };
  const versions = new Map([[release.index.tag, release]]);
  const backing = new Map();
  const cache = {
    async match(key) { return backing.get(String(key))?.clone(); },
    async put(key, value) { backing.set(String(key), value.clone()); },
    async delete(key) { backing.delete(String(key)); },
  };
  const harness = makeHarness({ latest: release, versions, clock, cache });

  const initial = await request(harness.worker, harness.env, "/remote/releases/metadata/targets.json");
  assert.equal(await initial.text(), "targets-0.1.0");
  clock.value += 60_001;
  harness.setLatest({ ...release, envelopeBytes: new TextEncoder().encode('{"signature":"bad","signed":{}}') });
  const duringPointerRewrite = await request(harness.worker, harness.env, "/remote/releases/metadata/targets.json");
  assert.equal(duringPointerRewrite.status, 200);
  assert.equal(await duringPointerRewrite.text(), "targets-0.1.0");

  clock.value = Date.parse(release.index.expiresAt);
  harness.setLatest(null);
  const afterSignedExpiry = await request(harness.worker, harness.env, "/remote/releases/metadata/targets.json");
  assert.equal(afterSignedExpiry.status, 503);
});

test("supports HEAD with validated installer headers and hides unrelated routes", async () => {
  const release = await makeRelease();
  const harness = makeHarness({ latest: release, versions: new Map([[release.index.tag, release]]) });
  const head = await request(harness.worker, harness.env, "/remote/install.sh", "HEAD");
  assert.equal(head.status, 200);
  assert.equal(head.headers.get("Content-Length"), String(release.index.files["install.sh"].size));
  assert.equal(await head.text(), "");
  assert.equal(harness.calls.some(({ url }) => url.endsWith("/install.sh")), false);

  const wrongRoute = await request(harness.worker, harness.env, "/remote/anything");
  assert.equal(wrongRoute.status, 404);
  assert.equal(harness.calls.length, 1); // only the signed envelope was fetched for HEAD
});
