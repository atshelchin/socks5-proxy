/**
 * VMess AEAD cryptographic primitives
 *
 * KDF matches v2ray-core's nested HMAC implementation exactly:
 * Each level uses the previous level's HMAC as its hash function.
 */

import { createHash, createHmac, createCipheriv, createDecipheriv } from "node:crypto";

// --- UUID ---

export function uuidToBytes(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ""), "hex");
}

// --- Command Key ---

const VMESS_AUTH_ID_SALT = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

export function computeCmdKey(uuidBytes: Buffer): Buffer {
  const h = createHash("md5");
  h.update(uuidBytes);
  h.update(VMESS_AUTH_ID_SALT);
  return h.digest();
}

// --- VMess KDF (nested HMAC-SHA256, matching v2ray-core exactly) ---
//
// v2ray's KDF builds a chain of HMAC hash functions:
//   Level 0: H0(·) = HMAC-SHA256(key="VMess AEAD KDF", msg=·)
//   Level 1: H1(·) = HMAC(key=path[0], hash=H0, msg=·)
//   Level N: HN(·) = HMAC(key=path[N-1], hash=H(N-1), msg=·)
//
// HMAC with a custom hash: HMAC_H(K, M) = H((K⊕opad) || H((K⊕ipad) || M))
// When H is itself an HMAC, this creates true nested HMACs.

const KDF_SALT = "VMess AEAD KDF";
const HMAC_BLOCK_SIZE = 64;

export function vmessKDF(key: Buffer, ...paths: (string | Buffer)[]): Buffer {
  return hashAtLevel(paths, paths.length, key);
}

function hashAtLevel(paths: (string | Buffer)[], level: number, data: Buffer): Buffer {
  if (level === 0) {
    // Base: standard HMAC-SHA256 keyed with "VMess AEAD KDF"
    return createHmac("sha256", KDF_SALT).update(data).digest();
  }

  // Manual HMAC: H(K⊕opad || H(K⊕ipad || M))
  // where H = hashAtLevel(level - 1)
  const pathKey = Buffer.from(paths[level - 1]!);

  // Normalize key to block size
  const K = Buffer.alloc(HMAC_BLOCK_SIZE);
  if (pathKey.length <= HMAC_BLOCK_SIZE) {
    pathKey.copy(K);
  } else {
    hashAtLevel(paths, level - 1, pathKey).copy(K);
  }

  const ipad = Buffer.alloc(HMAC_BLOCK_SIZE);
  const opad = Buffer.alloc(HMAC_BLOCK_SIZE);
  for (let i = 0; i < HMAC_BLOCK_SIZE; i++) {
    ipad[i] = K[i]! ^ 0x36;
    opad[i] = K[i]! ^ 0x5c;
  }

  const innerResult = hashAtLevel(paths, level - 1, Buffer.concat([ipad, data]));
  return hashAtLevel(paths, level - 1, Buffer.concat([opad, innerResult]));
}

// --- AuthID ---

export function generateAuthID(cmdKey: Buffer, timestamp: number): Buffer {
  const buf = Buffer.alloc(16);
  buf.writeBigUInt64BE(BigInt(timestamp), 0);
  const rand4 = Buffer.from(crypto.getRandomValues(new Uint8Array(4)));
  rand4.copy(buf, 8);
  const crc = crc32(buf.subarray(0, 12));
  buf.writeUInt32BE(crc >>> 0, 12);

  // AES key for AuthID = KDF16(cmdKey, "AES Auth ID Encryption")
  const aesKey = vmessKDF(cmdKey, "AES Auth ID Encryption").subarray(0, 16);
  const cipher = createCipheriv("aes-128-ecb", aesKey, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(buf), cipher.final()]);
}

// --- CRC32 (IEEE) ---

const crc32Table = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) {
    c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  crc32Table[i] = c;
}

export function crc32(data: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc = crc32Table[(crc ^ data[i]!) & 0xff]! ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// --- FNV-1a 32-bit ---

export function fnv1a32(data: Buffer): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < data.length; i++) {
    hash ^= data[i]!;
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

// --- AEAD wrappers ---

export function aeadSeal(
  algorithm: "aes-128-gcm" | "chacha20-poly1305",
  key: Buffer,
  nonce: Buffer,
  plaintext: Buffer,
  aad?: Buffer,
): Buffer {
  const cipher = createCipheriv(algorithm, key, nonce);
  if (aad && aad.length > 0) cipher.setAAD(aad);
  const encrypted = cipher.update(plaintext);
  cipher.final();
  const tag = cipher.getAuthTag();
  return Buffer.concat([encrypted, tag]);
}

export function aeadOpen(
  algorithm: "aes-128-gcm" | "chacha20-poly1305",
  key: Buffer,
  nonce: Buffer,
  ciphertext: Buffer,
  aad?: Buffer,
): Buffer {
  const tagStart = ciphertext.length - 16;
  const data = ciphertext.subarray(0, tagStart);
  const tag = ciphertext.subarray(tagStart);

  const decipher = createDecipheriv(algorithm, key, nonce);
  if (aad && aad.length > 0) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const decrypted = decipher.update(data);
  decipher.final();
  return Buffer.from(decrypted);
}

// --- Key/IV derivation for body ---

export function deriveRequestBodyKeyIV(
  dataKey: Buffer,
  dataIV: Buffer,
  security: "aes-128-gcm" | "chacha20-poly1305",
): { key: Buffer; iv: Buffer } {
  if (security === "aes-128-gcm") {
    return {
      key: createHash("sha256").update(dataKey).digest().subarray(0, 16),
      iv: createHash("sha256").update(dataIV).digest().subarray(0, 16),
    };
  } else {
    const md5_1 = createHash("md5").update(dataKey).digest();
    const md5_2 = createHash("md5").update(md5_1).digest();
    return {
      key: Buffer.concat([md5_1, md5_2]),
      iv: createHash("md5").update(dataIV).digest(),
    };
  }
}

export function deriveResponseBodyKeyIV(
  requestBodyKey: Buffer,
  requestBodyIV: Buffer,
  security: "aes-128-gcm" | "chacha20-poly1305",
): { key: Buffer; iv: Buffer } {
  if (security === "aes-128-gcm") {
    return {
      key: createHash("sha256").update(requestBodyKey).digest().subarray(0, 16),
      iv: createHash("sha256").update(requestBodyIV).digest().subarray(0, 16),
    };
  } else {
    const md5_1 = createHash("md5").update(requestBodyKey).digest();
    const md5_2 = createHash("md5").update(md5_1).digest();
    return {
      key: Buffer.concat([md5_1, md5_2]),
      iv: createHash("md5").update(requestBodyIV).digest(),
    };
  }
}
