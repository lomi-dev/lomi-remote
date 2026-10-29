const RELEASE_REPOSITORY = "lomi-dev/lomi-remote";
const INDEX_MAX_BYTES = 128 * 1024;
const SIGNATURE_BYTES = 64;
const MAX_FILES = 128;
const MAX_ASSET_BYTES = 1024 * 1024 * 1024;
const SMALL_FILE_BYTES = 1024 * 1024;
const MAX_SCRIPT_BYTES = 512 * 1024;
const MAX_METADATA_BYTES = 1024 * 1024;
const INDEX_CACHE_TTL_MS = 60_000;
const MAX_REDIRECTS = 5;
const CDN_HOSTS = new Set([
  "release-assets.githubusercontent.com",
  "objects.githubusercontent.com",
  "github-releases.githubusercontent.com",
]);
const STABLE_PLATFORMS = new Set([
  "linux-x86_64",
  "linux-aarch64",
  "macos-x86_64",
  "macos-aarch64",
  "windows-x86_64",
  "windows-aarch64",
]);

const RESPONSE_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "X-Robots-Tag": "noindex",
};

const FALLBACK_SHELL =
  "#!/bin/sh\nprintf '%s\\n' 'Lomi Remote installer: no authenticated release is currently available.' >&2\nexit 1\n";
const FALLBACK_POWERSHELL =
  "$ErrorActionPreference = 'Stop'\n[Console]::Error.WriteLine('Lomi Remote installer: no authenticated release is currently available.')\nexit 1\n";

export class GatewayError extends Error {
  constructor(status, publicMessage) {
    super(publicMessage);
    this.status = status;
    this.publicMessage = publicMessage;
  }
}

function fail(status, publicMessage) {
  throw new GatewayError(status, publicMessage);
}

function plainRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value, keys) {
  if (!plainRecord(value)) return false;
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function isAscii(value) {
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) > 0x7f) return false;
  }
  return true;
}

function canonicalJson(value, depth = 0) {
  if (depth > 64) fail(502, "Signed release index is malformed.");
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    if (typeof value === "string" && !isAscii(value)) {
      fail(502, "Signed release index is malformed.");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail(502, "Signed release index is malformed.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item, depth + 1)).join(",")}]`;
  }
  if (!plainRecord(value)) fail(502, "Signed release index is malformed.");
  const keys = Object.keys(value).sort();
  for (const key of keys) {
    if (!isAscii(key)) fail(502, "Signed release index is malformed.");
  }
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key], depth + 1)}`).join(",")}}`;
}

function strictVersion(value) {
  if (typeof value !== "string" || value.length > 128) return false;
  return /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(value);
}

function strictTag(value) {
  return typeof value === "string" && value.startsWith("v") && strictVersion(value.slice(1));
}

function safeLogicalPath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 255 ||
    !isAscii(value) ||
    value.startsWith("/") ||
    value.endsWith("/") ||
    value.includes("\\") ||
    value.includes("%") ||
    value.includes("//") ||
    !/^[A-Za-z0-9._/-]+$/.test(value)
  ) {
    return false;
  }
  return value.split("/").every((part) => part !== "." && part !== "..");
}

function safeAssetName(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 255 &&
    isAscii(value) && /^[A-Za-z0-9._-]+$/.test(value) && value !== "." && value !== "..";
}

function parseDate(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)
  ) {
    return null;
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return null;
  const canonical = new Date(milliseconds).toISOString();
  return canonical === value || canonical.replace(/\.000Z$/, "Z") === value ? milliseconds : null;
}

function decodeBase64(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    fail(503, "Release verification is not configured.");
  }
  let binary;
  try {
    binary = atob(value);
  } catch {
    fail(503, "Release verification is not configured.");
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.length !== 32 || bytesToBase64(bytes) !== value) {
    fail(503, "Release verification is not configured.");
  }
  return bytes;
}

function decodeSignature(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{86}==$/.test(value)) {
    fail(502, "Signed release index signature is malformed.");
  }
  let binary;
  try {
    binary = atob(value);
  } catch {
    fail(502, "Signed release index signature is malformed.");
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.length !== SIGNATURE_BYTES || bytesToBase64(bytes) !== value) {
    fail(502, "Signed release index signature is malformed.");
  }
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 1) {
    binary += String.fromCharCode(bytes[offset]);
  }
  return btoa(binary);
}

function bytesToHex(bytes) {
  let result = "";
  for (const byte of bytes) result += byte.toString(16).padStart(2, "0");
  return result;
}

function parseCanonicalEnvelope(envelopeBytes) {
  if (!(envelopeBytes instanceof Uint8Array) || envelopeBytes.length === 0 || envelopeBytes.length > INDEX_MAX_BYTES) {
    fail(502, "Signed release index is malformed.");
  }
  for (const byte of envelopeBytes) {
    if (byte > 0x7f) fail(502, "Signed release index is malformed.");
  }
  let source;
  let parsed;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(envelopeBytes);
    parsed = JSON.parse(source);
  } catch {
    fail(502, "Signed release index is malformed.");
  }
  if (canonicalJson(parsed) !== source || !hasExactKeys(parsed, ["signed", "signature"])) {
    fail(502, "Signed release index envelope is not canonical.");
  }
  const signedBytes = new TextEncoder().encode(canonicalJson(parsed.signed));
  const signatureBytes = decodeSignature(parsed.signature);
  return { signed: parsed.signed, signedBytes, signatureBytes };
}

function validateIndex(index, { repository, nowMs }) {
  const indexKeys = ["format", "repository", "tag", "version", "issuedAt", "expiresAt", "platforms", "files"];
  if (!hasExactKeys(index, indexKeys)) fail(502, "Signed release index is malformed.");
  if (
    index.format !== 1 ||
    index.repository !== repository ||
    !strictVersion(index.version) ||
    index.tag !== `v${index.version}` ||
    !strictTag(index.tag)
  ) {
    fail(502, "Signed release index does not match this repository.");
  }

  const issuedAt = parseDate(index.issuedAt);
  const expiresAt = parseDate(index.expiresAt);
  if (
    issuedAt === null ||
    expiresAt === null ||
    issuedAt > nowMs + 5 * 60_000 ||
    expiresAt <= nowMs ||
    expiresAt > issuedAt + 8 * 24 * 60 * 60_000
  ) {
    fail(502, "Signed release index is expired or outside its validity window.");
  }

  if (
    !Array.isArray(index.platforms) ||
    index.platforms.length === 0 ||
    index.platforms.length > STABLE_PLATFORMS.size ||
    index.platforms.some((platform) => typeof platform !== "string" || !STABLE_PLATFORMS.has(platform)) ||
    new Set(index.platforms).size !== index.platforms.length
  ) {
    fail(502, "Signed release index has an invalid platform list.");
  }

  if (!plainRecord(index.files)) fail(502, "Signed release index has an invalid file map.");
  const paths = Object.keys(index.files);
  if (paths.length === 0 || paths.length > MAX_FILES) fail(502, "Signed release index has an invalid file map.");
  const assets = new Set();
  for (const logicalPath of paths) {
    const file = index.files[logicalPath];
    if (
      !safeLogicalPath(logicalPath) ||
      !hasExactKeys(file, ["asset", "size", "sha256"]) ||
      !safeAssetName(file.asset) ||
      !Number.isSafeInteger(file.size) ||
      file.size <= 0 ||
      file.size > MAX_ASSET_BYTES ||
      typeof file.sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(file.sha256) ||
      assets.has(file.asset)
    ) {
      fail(502, "Signed release index has an invalid file entry.");
    }
    if ((logicalPath === "install.sh" || logicalPath === "install.ps1") && file.size > MAX_SCRIPT_BYTES) {
      fail(502, "Signed release index has an oversized installer.");
    }
    if (logicalPath.startsWith("metadata/") && file.size > MAX_METADATA_BYTES) {
      fail(502, "Signed release index has oversized TUF metadata.");
    }
    assets.add(file.asset);
  }
  return index;
}

export async function verifyReleaseEnvelope(envelopeBytes, {
  publicKey,
  repository = RELEASE_REPOSITORY,
  nowMs = Date.now(),
  cryptoImpl = globalThis.crypto,
} = {}) {
  const { signed: index, signedBytes, signatureBytes } = parseCanonicalEnvelope(envelopeBytes);
  if (!strictTag(index?.tag)) fail(502, "Signed release index has an invalid tag.");
  let importedKey;
  let verified;
  try {
    const rawPublicKey = publicKey instanceof Uint8Array ? publicKey : decodeBase64(publicKey);
    if (rawPublicKey.length !== 32) fail(503, "Release verification is not configured.");
    importedKey = await cryptoImpl.subtle.importKey("raw", rawPublicKey, { name: "Ed25519" }, false, ["verify"]);
    verified = await cryptoImpl.subtle.verify({ name: "Ed25519" }, importedKey, signatureBytes, signedBytes);
  } catch (error) {
    if (error instanceof GatewayError) throw error;
    fail(503, "Release verification is unavailable.");
  }
  if (!verified) fail(502, "Signed release index signature is invalid.");
  return validateIndex(index, { repository, nowMs });
}

function safeGithubUrl(input, repository) {
  const raw = String(input);
  const rawPath = raw.split(/[?#]/, 1)[0];
  if (
    raw.includes("\\") ||
    /%(?:2e|2f|5c)/i.test(rawPath) ||
    /(?:^|\/)\.{1,2}(?:\/|$)/.test(rawPath)
  ) {
    fail(502, "Release service returned an unsafe redirect.");
  }
  let url;
  try {
    url = new URL(raw);
  } catch {
    fail(502, "Release service returned an unsafe redirect.");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    url.port ||
    url.hostname.endsWith(".") ||
    url.pathname.includes("%")
  ) {
    fail(502, "Release service returned an unsafe redirect.");
  }
  const authorityMatch = raw.match(/^(?:https:)?\/\/([^/?#]*)/i);
  if (authorityMatch && authorityMatch[1] !== url.hostname) {
    fail(502, "Release service returned an unsafe redirect.");
  }

  if (url.hostname === "github.com") {
    if (url.search) fail(502, "Release service returned an unsafe redirect.");
    const repoPath = repository.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const allowed = new RegExp(
      `^/${repoPath}/releases/(?:latest/download/release-index(?:-recovery)?\\.json|download/v(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)/[A-Za-z0-9._-]+)$`,
    );
    if (!allowed.test(url.pathname)) fail(502, "Release service returned an unsafe redirect.");
    return url;
  }

  if (CDN_HOSTS.has(url.hostname) && url.pathname.startsWith("/")) return url;
  fail(502, "Release service returned an unsafe redirect.");
}

function safeRedirectLocation(location) {
  const rawPath = location.split(/[?#]/, 1)[0];
  const authorityMatch = location.match(/^(?:https:)?\/\/([^/?#]*)/i);
  if (
    location.includes("\\") ||
    /%(?:2e|2f|5c)/i.test(rawPath) ||
    /(?:^|\/)\.{1,2}(?:\/|$)/.test(rawPath) ||
    (authorityMatch && (authorityMatch[1].includes(":") || authorityMatch[1].includes("@")))
  ) {
    fail(502, "Release service returned an unsafe redirect.");
  }
}

function initialGithubUrl(repository, suffix) {
  return safeGithubUrl(`https://github.com/${repository}${suffix}`, repository);
}

async function cancelBody(response) {
  try {
    await response.body?.cancel();
  } catch {
    // Discarding redirect and error bodies is best effort.
  }
}

async function fetchGithub(url, { repository, fetchImpl }) {
  let current = safeGithubUrl(url, repository);
  for (let redirects = 0; ; redirects += 1) {
    let response;
    try {
      response = await fetchImpl(current.href, {
        method: "GET",
        redirect: "manual",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        headers: { Accept: "application/octet-stream" },
      });
    } catch {
      fail(503, "Release service is temporarily unavailable.");
    }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("Location");
      await cancelBody(response);
      if (!location || redirects >= MAX_REDIRECTS) fail(502, "Release service returned an invalid redirect.");
      safeRedirectLocation(location);
      current = safeGithubUrl(new URL(location, current).href, repository);
      continue;
    }
    return response;
  }
}

function contentLength(response) {
  const header = response.headers.get("Content-Length");
  if (header === null) return null;
  if (!/^(0|[1-9][0-9]*)$/.test(header)) fail(502, "Release service returned an invalid file size.");
  const value = Number(header);
  if (!Number.isSafeInteger(value)) fail(502, "Release service returned an invalid file size.");
  return value;
}

async function readBounded(response, { maxBytes, exactBytes = null }) {
  const declared = contentLength(response);
  if ((declared !== null && declared > maxBytes) || (exactBytes !== null && declared !== null && declared !== exactBytes)) {
    await cancelBody(response);
    fail(502, "Release service returned a file with an invalid size.");
  }
  const reader = response.body?.getReader();
  if (!reader) fail(502, "Release service returned an empty file.");
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes || (exactBytes !== null && total > exactBytes)) {
        await reader.cancel();
        fail(502, "Release service returned a file with an invalid size.");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof GatewayError) throw error;
    fail(502, "Release service returned an incomplete file.");
  } finally {
    try { reader.releaseLock(); } catch { /* already released */ }
  }
  if ((exactBytes !== null && total !== exactBytes) || (declared !== null && total !== declared)) {
    fail(502, "Release service returned an incomplete file.");
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function indexCacheKey(repository, publicKeyBase64, origin, variant) {
  return `${origin}/__lomi_release_gateway_cache/${encodeURIComponent(repository)}/${encodeURIComponent(publicKeyBase64)}/${variant}`;
}

async function readCachedIndex(cache, key, { repository, publicKey, expectedTag = null, nowMs, cryptoImpl }) {
  if (!cache) return null;
  try {
    const cached = await cache.match(key);
    if (!cached) return null;
    const cacheExpiresAt = Number(cached.headers.get("X-Lomi-Cache-Expires"));
    if (!Number.isSafeInteger(cacheExpiresAt) || cacheExpiresAt <= nowMs) {
      await cache.delete?.(key);
      return null;
    }
    const envelopeBytes = await readBounded(cached, { maxBytes: INDEX_MAX_BYTES });
    const index = await verifyReleaseEnvelope(envelopeBytes, {
      publicKey,
      repository,
      nowMs,
      cryptoImpl,
    });
    if (expectedTag !== null && index.tag !== expectedTag) {
      fail(502, "Cached release index does not match the requested version.");
    }
    return { index, envelopeBytes };
  } catch {
    try { await cache.delete?.(key); } catch { /* cache is optional */ }
    return null;
  }
}

async function storeCachedIndex(cache, key, envelopeBytes, nowMs, expiresAt, requestedTtlMs) {
  if (!cache) return;
  const ttlMs = Math.min(requestedTtlMs, expiresAt - nowMs);
  const ttlSeconds = Math.floor(ttlMs / 1000);
  if (ttlSeconds < 1) return;
  try {
    const headers = {
      "Cache-Control": `public, max-age=${ttlSeconds}`,
      "Content-Type": "application/octet-stream",
      "X-Lomi-Cache-Expires": String(nowMs + ttlMs),
    };
    await cache.put(key, new Response(envelopeBytes, { headers }));
  } catch {
    // Internal caching is an optimization; verified origin data still serves.
  }
}

async function fetchIndexAsset(tag, assetName, {
  repository,
  publicKey,
  nowMs,
  cryptoImpl,
  fetchImpl,
  missingStatus,
}) {
  const indexUrl = tag === null
    ? initialGithubUrl(repository, `/releases/latest/download/${assetName}`)
    : initialGithubUrl(repository, `/releases/download/${tag}/${assetName}`);
  let indexResponse;
  try {
    indexResponse = await fetchGithub(indexUrl.href, { repository, fetchImpl });
  } catch (error) {
    if (error instanceof GatewayError) throw error;
    fail(503, "Release service is temporarily unavailable.");
  }
  if (indexResponse.status === 404) {
    await cancelBody(indexResponse);
    fail(missingStatus, tag === null ? "No signed release is currently available." : "Release not found.");
  }
  if (indexResponse.status !== 200) {
    await cancelBody(indexResponse);
    fail(indexResponse.status >= 500 ? 503 : 502, "Release service is temporarily unavailable.");
  }
  const envelopeBytes = await readBounded(indexResponse, { maxBytes: INDEX_MAX_BYTES });
  const untrusted = parseCanonicalEnvelope(envelopeBytes);
  const index = untrusted.signed;
  if (!strictTag(index?.tag)) fail(502, "Signed release index has an invalid tag.");
  if (tag !== null && index.tag !== tag) fail(502, "Signed release index does not match the requested version.");

  await verifyReleaseEnvelope(envelopeBytes, {
    publicKey,
    repository,
    nowMs,
    cryptoImpl,
  });
  return { index, envelopeBytes };
}

async function fetchIndexFromTag(tag, options) {
  let primaryError;
  try {
    return await fetchIndexAsset(tag, "release-index.json", options);
  } catch (error) {
    primaryError = error;
  }
  try {
    return await fetchIndexAsset(tag, "release-index-recovery.json", options);
  } catch {
    throw primaryError;
  }
}

function headersFor(contentType, size = null) {
  const headers = new Headers(RESPONSE_HEADERS);
  headers.set("Content-Type", contentType);
  if (size !== null) headers.set("Content-Length", String(size));
  return headers;
}

function response(status, body = "", contentType = "text/plain;charset=utf-8", size = null, head = false, extra = {}) {
  const headers = headersFor(contentType, size);
  for (const [name, value] of Object.entries(extra)) headers.set(name, value);
  return new Response(head ? null : body, { status, headers });
}

function errorResponse(error, { head = false } = {}) {
  const status = error instanceof GatewayError ? error.status : 503;
  const message = error instanceof GatewayError ? error.publicMessage : "Release service is temporarily unavailable.";
  return response(status, `${message}\n`, "text/plain;charset=utf-8", null, head);
}

function installerFailure(path, head) {
  const shell = path === "/remote/install.sh";
  const body = shell ? FALLBACK_SHELL : FALLBACK_POWERSHELL;
  return response(503, body, "text/plain;charset=utf-8", new TextEncoder().encode(body).length, head);
}

function parseReleaseRoute(pathname) {
  const prefix = "/remote/releases/";
  if (!pathname.startsWith(prefix)) return null;
  const remaining = pathname.slice(prefix.length);
  if (!remaining || remaining.includes("%") || !isAscii(remaining)) return { invalid: true };
  const firstSlash = remaining.indexOf("/");
  if (firstSlash > 0) {
    const possibleTag = remaining.slice(0, firstSlash);
    if (possibleTag.startsWith("v")) {
      if (!strictTag(possibleTag)) return { invalid: true };
      const logicalPath = remaining.slice(firstSlash + 1);
      if (!safeLogicalPath(logicalPath)) return { invalid: true };
      return { tag: possibleTag, logicalPath };
    }
  }
  if (!safeLogicalPath(remaining)) return { invalid: true };
  return { tag: null, logicalPath: remaining };
}

function streamExactSize(body, expectedSize) {
  const reader = body?.getReader();
  if (!reader) fail(502, "Release service returned an empty file.");
  let total = 0;
  let finished = false;
  return new ReadableStream({
    async pull(controller) {
      if (finished) return;
      try {
        const { done, value } = await reader.read();
        if (done) {
          finished = true;
          try { reader.releaseLock(); } catch { /* already released */ }
          if (total !== expectedSize) throw new Error("unexpected stream length");
          controller.close();
          return;
        }
        total += value.byteLength;
        if (total > expectedSize) throw new Error("unexpected stream length");
        controller.enqueue(value);
      } catch {
        finished = true;
        try { await reader.cancel(); } catch { /* source is already closed */ }
        try { reader.releaseLock(); } catch { /* already released */ }
        controller.error(new Error("Release asset size did not match its signed index entry."));
      }
    },
    async cancel(reason) {
      finished = true;
      try { await reader.cancel(reason); } catch { /* source is already closed */ }
      try { reader.releaseLock(); } catch { /* already released */ }
    },
  });
}

async function serveReleaseFile(route, request, config) {
  const { index, envelopeBytes } = route.tag === null
    ? await config.loadLatest()
    : await config.loadVersion(route.tag);
  const { logicalPath } = route;

  if (logicalPath === "release-index.json") {
    return response(200, envelopeBytes, "application/json;charset=utf-8", envelopeBytes.length, request.method === "HEAD");
  }
  if (logicalPath === "latest.json") {
    const latest = {
      version: index.version,
      tag: index.tag,
      platforms: index.platforms,
      releaseUrl: `https://github.com/${config.repository}/releases/tag/${index.tag}`,
    };
    const latestBytes = new TextEncoder().encode(JSON.stringify(latest));
    return response(200, latestBytes, "application/json;charset=utf-8", latestBytes.length, request.method === "HEAD");
  }

  const file = index.files[logicalPath];
  if (!file) return response(404, "Not found.\n", "text/plain;charset=utf-8", null, request.method === "HEAD");
  const contentType = "application/octet-stream";
  if (request.method === "HEAD") return response(200, null, contentType, file.size, true);

  const fileUrl = initialGithubUrl(
    config.repository,
    `/releases/download/${index.tag}/${file.asset}`,
  );
  const fileResponse = await fetchGithub(fileUrl.href, {
    repository: config.repository,
    fetchImpl: config.fetchImpl,
  });
  if (fileResponse.status !== 200) {
    await cancelBody(fileResponse);
    fail(502, "Signed release asset is temporarily unavailable.");
  }
  const upstreamLength = contentLength(fileResponse);
  if (upstreamLength !== null && upstreamLength !== file.size) {
    await cancelBody(fileResponse);
    fail(502, "Signed release asset has an invalid size.");
  }
  if (file.size <= SMALL_FILE_BYTES) {
    const bytes = await readBounded(fileResponse, { maxBytes: file.size, exactBytes: file.size });
    let digest;
    try {
      digest = bytesToHex(new Uint8Array(await config.cryptoImpl.subtle.digest("SHA-256", bytes)));
    } catch {
      fail(503, "Release verification is unavailable.");
    }
    if (digest !== file.sha256) fail(502, "Signed release asset failed its digest check.");
    return response(200, bytes, contentType, bytes.length);
  }
  return new Response(streamExactSize(fileResponse.body, file.size), {
    status: 200,
    headers: headersFor(contentType, file.size),
  });
}

export function createReleaseWorker({
  fetchImpl = globalThis.fetch,
  cryptoImpl = globalThis.crypto,
  cache = globalThis.caches?.default,
  now = () => Date.now(),
} = {}) {
  async function makeConfig(env, requestOrigin) {
    const repository = env?.REPOSITORY;
    if (repository !== RELEASE_REPOSITORY) fail(503, "Release verification is not configured.");
    const publicKeyBase64 = env?.RELEASE_INDEX_PUBLIC_KEY;
    const publicKey = decodeBase64(publicKeyBase64);
    if (typeof fetchImpl !== "function" || !cryptoImpl?.subtle) {
      fail(503, "Release verification is unavailable.");
    }
    const latestCacheKey = indexCacheKey(repository, publicKeyBase64, requestOrigin, "latest");
    const staleLatestCacheKey = indexCacheKey(repository, publicKeyBase64, requestOrigin, "latest-stale");
    const versionCacheKey = (tag) => indexCacheKey(
      repository,
      publicKeyBase64,
      requestOrigin,
      `versions/${encodeURIComponent(tag)}`,
    );
    const staleVersionCacheKey = (tag) => indexCacheKey(
      repository,
      publicKeyBase64,
      requestOrigin,
      `versions-stale/${encodeURIComponent(tag)}`,
    );

    const loadVersion = async (tag) => {
      const nowMs = now();
      const key = versionCacheKey(tag);
      const cached = await readCachedIndex(cache, key, { repository, publicKey, expectedTag: tag, nowMs, cryptoImpl });
      if (cached) return cached;
      const staleKey = staleVersionCacheKey(tag);
      const fallback = await readCachedIndex(cache, staleKey, { repository, publicKey, expectedTag: tag, nowMs, cryptoImpl });
      let result;
      try {
        result = await fetchIndexFromTag(tag, {
          repository,
          publicKey,
          nowMs,
          cryptoImpl,
          fetchImpl,
          missingStatus: 404,
        });
      } catch (error) {
        if (fallback) return fallback;
        throw error;
      }
      const expiresAt = parseDate(result.index.expiresAt);
      await storeCachedIndex(cache, key, result.envelopeBytes, nowMs, expiresAt, INDEX_CACHE_TTL_MS);
      await storeCachedIndex(cache, staleKey, result.envelopeBytes, nowMs, expiresAt, expiresAt - nowMs);
      return result;
    };
    const loadLatest = async () => {
      const nowMs = now();
      const cached = await readCachedIndex(cache, latestCacheKey, { repository, publicKey, nowMs, cryptoImpl });
      if (cached) return cached;
      const fallback = await readCachedIndex(cache, staleLatestCacheKey, { repository, publicKey, nowMs, cryptoImpl });
      let result;
      try {
        result = await fetchIndexFromTag(null, {
          repository,
          publicKey,
          nowMs,
          cryptoImpl,
          fetchImpl,
          missingStatus: 503,
        });
      } catch (error) {
        if (fallback) return fallback;
        throw error;
      }
      const expiresAt = parseDate(result.index.expiresAt);
      await storeCachedIndex(cache, latestCacheKey, result.envelopeBytes, nowMs, expiresAt, INDEX_CACHE_TTL_MS);
      await storeCachedIndex(cache, staleLatestCacheKey, result.envelopeBytes, nowMs, expiresAt, expiresAt - nowMs);
      return result;
    };
    return { repository, cryptoImpl, fetchImpl, loadLatest, loadVersion };
  }

  return async function handleRequest(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const isInstaller = pathname === "/remote/install.sh" || pathname === "/remote/install.ps1";
    const releaseRoute = pathname.startsWith("/remote/releases/") ? parseReleaseRoute(pathname) : null;
    if (!isInstaller && releaseRoute === null) return response(404, "Not found.\n");
    if (releaseRoute?.invalid) return response(404, "Not found.\n");
    if (request.method !== "GET" && request.method !== "HEAD") {
      return response(405, "Method not allowed.\n", "text/plain;charset=utf-8", null, false, { Allow: "GET, HEAD" });
    }
    const head = request.method === "HEAD";
    if (isInstaller) {
      try {
        const config = await makeConfig(env, url.origin);
        const { index } = await config.loadLatest();
        const logicalPath = pathname.endsWith("install.sh") ? "install.sh" : "install.ps1";
        const file = index.files[logicalPath];
        if (!file) return installerFailure(pathname, head);
        const assetRoute = { tag: null, logicalPath };
        return await serveInstaller(assetRoute, file, request, config, index);
      } catch {
        return installerFailure(pathname, head);
      }
    }
    try {
      const config = await makeConfig(env, url.origin);
      return await serveReleaseFile(releaseRoute, request, config);
    } catch (error) {
      return errorResponse(error, { head });
    }
  };
}

async function serveInstaller(route, file, request, config, index) {
  if (request.method === "HEAD") {
    return response(200, null, "text/plain;charset=utf-8", file.size, true);
  }
  const fileUrl = initialGithubUrl(config.repository, `/releases/download/${index.tag}/${file.asset}`);
  const upstream = await fetchGithub(fileUrl.href, {
    repository: config.repository,
    fetchImpl: config.fetchImpl,
  });
  if (upstream.status !== 200) {
    await cancelBody(upstream);
    return installerFailure(route.logicalPath === "install.sh" ? "/remote/install.sh" : "/remote/install.ps1", request.method === "HEAD");
  }
  const bytes = await readBounded(upstream, { maxBytes: MAX_SCRIPT_BYTES, exactBytes: file.size });
  const digest = bytesToHex(new Uint8Array(await config.cryptoImpl.subtle.digest("SHA-256", bytes)));
  if (digest !== file.sha256) fail(502, "Signed release installer failed its digest check.");
  return response(200, bytes, "text/plain;charset=utf-8", bytes.length);
}

const defaultWorker = createReleaseWorker();

export default {
  fetch(request, env, context) {
    void context;
    return defaultWorker(request, env);
  },
};
