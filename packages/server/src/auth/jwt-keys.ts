import crypto from 'crypto';

/**
 * JWT signing key set with rotation support.
 *
 * Keys are configured as a comma-separated list of `kid:secret` pairs in
 * `LUMEN_JWT_KEYS` (newest first). The first entry is the active signing key;
 * every non-expired entry is accepted for verification, so rotation happens
 * without downtime. `LUMEN_JWT_SECRET` is still honoured as a legacy key with
 * the kid `legacy`.
 *
 * Optional expiry: `kid:secret:expiresAt` where `expiresAt` is a unix
 * timestamp in seconds (or an ISO-8601 date). Expired keys are pruned from
 * the set and never used for signing or verification.
 */

export interface JwtKey {
  kid: string;
  secret: string;
  /** Unix seconds after which the key is no longer accepted. */
  expiresAt?: number;
}

export interface JwtKeySet {
  /** Key used to sign new tokens (newest non-expired key). */
  active: JwtKey;
  /** All non-expired keys, active first. */
  keys: JwtKey[];
}

const KID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

function parseExpiry(raw: string | undefined): number | undefined {
  if (!raw) {
    return undefined;
  }
  const trimmed = raw.trim();
  if (/^\d+$/.test(trimmed)) {
    return Number(trimmed);
  }
  const parsed = Date.parse(trimmed);
  return Number.isNaN(parsed) ? undefined : Math.floor(parsed / 1000);
}

function parseKeyEntry(entry: string): JwtKey | null {
  const trimmed = entry.trim();
  if (!trimmed) {
    return null;
  }
  const firstColon = trimmed.indexOf(':');
  if (firstColon <= 0) {
    return null;
  }
  const kid = trimmed.slice(0, firstColon).trim();
  const rest = trimmed.slice(firstColon + 1);
  const secondColon = rest.indexOf(':');
  const secret = (secondColon === -1 ? rest : rest.slice(0, secondColon)).trim();
  const expiresAt = secondColon === -1 ? undefined : parseExpiry(rest.slice(secondColon + 1));

  if (!KID_PATTERN.test(kid) || secret.length === 0) {
    return null;
  }
  return { kid, secret, expiresAt };
}

/**
 * Parse a raw key list into a key set, pruning expired keys.
 * Returns null when no usable key remains.
 */
export function parseJwtKeySet(raw: string | undefined, nowSeconds = Math.floor(Date.now() / 1000)): JwtKeySet | null {
  if (!raw) {
    return null;
  }
  const seen = new Set<string>();
  const keys: JwtKey[] = [];
  for (const entry of raw.split(',')) {
    const key = parseKeyEntry(entry);
    if (!key || seen.has(key.kid)) {
      continue;
    }
    if (typeof key.expiresAt === 'number' && nowSeconds >= key.expiresAt) {
      continue; // expired: prune
    }
    seen.add(key.kid);
    keys.push(key);
  }
  if (keys.length === 0) {
    return null;
  }
  return { active: keys[0], keys };
}

/**
 * Resolve the key set from the environment, falling back to the legacy
 * single-secret configuration.
 */
export function resolveJwtKeySet(env: NodeJS.ProcessEnv = process.env): JwtKeySet | null {
  const fromList = parseJwtKeySet(env.LUMEN_JWT_KEYS);
  if (fromList) {
    return fromList;
  }
  const legacy = env.LUMEN_JWT_SECRET || env.JWT_SECRET;
  if (!legacy) {
    return null;
  }
  return { active: { kid: 'legacy', secret: legacy }, keys: [{ kid: 'legacy', secret: legacy }] };
}

function base64UrlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(input: string): Buffer {
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  return Buffer.from(input.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function sign(headerB64: string, payloadB64: string, secret: string): string {
  return base64UrlEncode(
    crypto.createHmac('sha256', secret).update(`${headerB64}.${payloadB64}`).digest(),
  );
}

/**
 * Sign a payload with the active key, embedding the `kid` header.
 */
export function signJwt(
  payload: Record<string, unknown>,
  keySet: JwtKeySet,
  expiresInSeconds: number,
): string {
  const issuedAt = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT', kid: keySet.active.kid };
  const headerB64 = base64UrlEncode(Buffer.from(JSON.stringify(header), 'utf8'));
  const payloadB64 = base64UrlEncode(
    Buffer.from(JSON.stringify({ ...payload, iat: issuedAt, exp: issuedAt + expiresInSeconds }), 'utf8'),
  );
  return `${headerB64}.${payloadB64}.${sign(headerB64, payloadB64, keySet.active.secret)}`;
}

/**
 * Verify a token against any active key. When the header carries a `kid` only
 * that key is tried; otherwise every active key is tried in order.
 * Returns the decoded payload, or null when the token is invalid or expired.
 */
export function verifyJwtWithKeySet(
  token: string,
  keySet: JwtKeySet,
  nowSeconds = Math.floor(Date.now() / 1000),
): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return null;
  }
  const [headerB64, payloadB64, signatureB64] = parts;

  let header: { alg?: string; kid?: string };
  try {
    header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
  } catch {
    return null;
  }
  if (!header || header.alg !== 'HS256') {
    return null;
  }

  const candidates = header.kid
    ? keySet.keys.filter((k) => k.kid === header.kid)
    : keySet.keys;
  if (candidates.length === 0) {
    return null;
  }

  const valid = candidates.some((key) => safeEqual(sign(headerB64, payloadB64, key.secret), signatureB64));
  if (!valid) {
    return null;
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
  } catch {
    return null;
  }

  if (typeof payload.exp === 'number' && nowSeconds >= payload.exp) {
    return null;
  }
  if (typeof payload.nbf === 'number' && nowSeconds < payload.nbf) {
    return null;
  }
  return payload;
}

/**
 * JWKS-style public description of the key set (no secrets).
 */
export function toJwks(keySet: JwtKeySet): { keys: Array<{ kid: string; alg: string; kty: string; use: string }> } {
  return {
    keys: keySet.keys.map((key) => ({ kid: key.kid, alg: 'HS256', kty: 'oct', use: 'sig' })),
  };
}
