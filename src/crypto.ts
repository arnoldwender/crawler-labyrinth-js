import { sanitizeSeed } from './config.js';

const encoder = new TextEncoder();

export async function hmacSha256Hex(message: string, secret: string): Promise<string> {
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await globalThis.crypto.subtle.sign('HMAC', key, encoder.encode(message));
  const bytes = new Uint8Array(sig);
  let hex = '';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Constant-time hex string comparison avoiding early-exit timing side channels.
 */
export function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length || a.length === 0) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function parseIpv4Quad(part: string): [number, number] | null {
  const octets = part.split('.');
  if (octets.length !== 4) {
    return null;
  }
  const nums: number[] = [];
  for (const octet of octets) {
    if (!/^\d{1,3}$/.test(octet)) {
      return null;
    }
    const n = Number(octet);
    if (n < 0 || n > 255) {
      return null;
    }
    nums.push(n);
  }
  return [((nums[0]! << 8) | nums[1]!) >>> 0, ((nums[2]! << 8) | nums[3]!) >>> 0];
}

function canonicalizeIpv6(lowerIp: string): string | null {
  const dblIdx = lowerIp.indexOf('::');
  if (dblIdx !== -1 && lowerIp.indexOf('::', dblIdx + 2) !== -1) {
    return null;
  }

  const parseSegmentList = (segStr: string): number[] | null => {
    if (segStr === '') {
      return [];
    }
    const parts = segStr.split(':');
    const out: number[] = [];
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i]!;
      if (part.includes('.')) {
        if (i !== parts.length - 1) {
          return null;
        }
        const quad = parseIpv4Quad(part);
        if (!quad) {
          return null;
        }
        out.push(quad[0], quad[1]);
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/.test(part)) {
        return null;
      }
      out.push(Number.parseInt(part, 16));
    }
    return out;
  };

  let groups: number[] | null = null;
  if (dblIdx === -1) {
    const parsed = parseSegmentList(lowerIp);
    if (parsed && parsed.length === 8) {
      groups = parsed;
    }
  } else {
    const leftStr = lowerIp.slice(0, dblIdx);
    const rightStr = lowerIp.slice(dblIdx + 2);
    const left = parseSegmentList(leftStr);
    const right = parseSegmentList(rightStr);
    if (left && right && left.length + right.length < 8) {
      const zeroCount = 8 - left.length - right.length;
      groups = [...left, ...new Array<number>(zeroCount).fill(0), ...right];
    }
  }

  if (!groups || groups.length !== 8) {
    return null;
  }

  // Extract IPv4 from any IPv4-mapped IPv6 form (`::ffff:a.b.c.d`, `0:0:0:0:0:ffff:...`, `::ffff:c633:6407`).
  if (
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0xffff
  ) {
    const hi = groups[6]!;
    const lo = groups[7]!;
    return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
  }

  // RFC 5952 longest run of >=2 consecutive zero groups (leftmost wins ties).
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) {
        curStart = i;
        curLen = 1;
      } else {
        curLen++;
      }
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  if (bestLen < 2) {
    return groups.map((g) => g.toString(16)).join(':');
  }
  const before = groups.slice(0, bestStart).map((g) => g.toString(16)).join(':');
  const after = groups.slice(bestStart + bestLen).map((g) => g.toString(16)).join(':');
  return `${before}::${after}`;
}

/**
 * Normalizes client IP strings so IPv6 compression variants, IPv4-mapped IPv6 forms,
 * bracketed `[::1]:port`, IPv4 `ip:port`, and zone suffixes resolve deterministically.
 */
export function normalizeClientIp(rawIp: string): string {
  let ip = rawIp.trim();
  if (!ip) {
    return '';
  }

  const bracketed = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(ip);
  if (bracketed && bracketed[1]) {
    ip = bracketed[1];
  } else {
    const ipv4Port = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(ip);
    if (ipv4Port && ipv4Port[1]) {
      ip = ipv4Port[1];
    }
  }

  const zoneIdx = ip.indexOf('%');
  if (zoneIdx > 0) {
    ip = ip.slice(0, zoneIdx);
  }

  ip = ip.toLowerCase();
  if (ip.includes(':')) {
    return canonicalizeIpv6(ip) ?? '';
  }
  const quad = parseIpv4Quad(ip);
  if (!quad) {
    return '';
  }
  const [hi, lo] = quad;
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

export async function signTrapToken(depth: number, seed: string, secret: string): Promise<string> {
  const boundedDepth = Math.max(1, Math.min(16, Math.trunc(depth)));
  const cleanSeed = sanitizeSeed(seed);
  const digest = await hmacSha256Hex(`${boundedDepth}|${cleanSeed}`, secret);
  return `${boundedDepth}-${cleanSeed}-${digest.slice(0, 16)}`;
}

export interface ParsedTrapToken {
  readonly depth: number;
  readonly seed: string;
}

export async function verifyTrapToken(token: string, secret: string): Promise<ParsedTrapToken | null> {
  const match = /^([1-9][0-9]?)-([a-z0-9]{4,24})-([a-f0-9]{16})$/.exec(token);
  if (!match) {
    return null;
  }
  const depth = Number(match[1]);
  const seed = match[2];
  const actualSig = match[3];
  if (!Number.isInteger(depth) || depth < 1 || depth > 16 || !seed || !actualSig) {
    return null;
  }
  const expectedSig = (await hmacSha256Hex(`${depth}|${seed}`, secret)).slice(0, 16);
  if (!timingSafeEqualHex(expectedSig, actualSig)) {
    return null;
  }
  return { depth, seed };
}

/**
 * Privacy-safe daily keyed HMAC digest of a normalized client IP. Raw IPs are never stored.
 */
export async function hashClientIp(rawIp: string, secret: string, utcDay?: string): Promise<string> {
  const day = utcDay ?? new Date().toISOString().slice(0, 10);
  const normalized = normalizeClientIp(rawIp);
  const ip = normalized.length > 0 ? normalized : '0.0.0.0';
  return hmacSha256Hex(`${ip}|${day}`, secret);
}
