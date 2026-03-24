/**
 * VMess chunked stream encoder/decoder
 *
 * Option 0x01 (chunk stream, no masking):
 *   [2 bytes BE length (plaintext_len + 16)] [AEAD-encrypted payload]
 *
 * Length field includes the GCM tag (16 bytes).
 */

import { aeadSeal, aeadOpen } from "./crypto";

const AEAD_TAG_SIZE = 16;
const MAX_CHUNK_SIZE = 1 << 14; // 16KB

type AeadAlgo = "aes-128-gcm" | "chacha20-poly1305";

function makeNonce(baseIV: Buffer, count: number): Buffer {
  const nonce = Buffer.alloc(12);
  baseIV.copy(nonce, 0, 0, 12);
  nonce.writeUInt16BE(count, 0);
  return nonce;
}

// ============================================================
// Encoder
// ============================================================

export function createChunkEncoder(
  key: Buffer,
  iv: Buffer,
  algorithm: AeadAlgo,
) {
  let count = 0;

  return function encode(plaintext: Buffer): Buffer {
    const chunks: Buffer[] = [];
    let offset = 0;

    while (offset < plaintext.length) {
      const end = Math.min(offset + MAX_CHUNK_SIZE, plaintext.length);
      const chunk = plaintext.subarray(offset, end);

      // Encrypt payload
      const nonce = makeNonce(iv, count++);
      const encrypted = aeadSeal(algorithm, key, nonce, chunk);

      // 2-byte length header (includes tag)
      const lenBuf = Buffer.alloc(2);
      lenBuf.writeUInt16BE(encrypted.length, 0);

      chunks.push(lenBuf, encrypted);
      offset = end;
    }

    return Buffer.concat(chunks);
  };
}

// ============================================================
// Decoder
// ============================================================

export function createChunkDecoder(
  key: Buffer,
  iv: Buffer,
  algorithm: AeadAlgo,
) {
  let count = 0;
  let buffer = Buffer.alloc(0);

  return function decode(data: Buffer): Buffer[] {
    buffer = buffer.length === 0 ? data : Buffer.concat([buffer, data]);
    const results: Buffer[] = [];

    while (buffer.length >= 2) {
      const chunkLen = buffer.readUInt16BE(0);

      if (chunkLen === 0) {
        // End of stream
        buffer = buffer.subarray(2);
        break;
      }

      if (buffer.length < 2 + chunkLen) break;

      const encrypted = buffer.subarray(2, 2 + chunkLen);
      buffer = buffer.subarray(2 + chunkLen);

      const nonce = makeNonce(iv, count++);
      const plaintext = aeadOpen(algorithm, key, nonce, encrypted);
      results.push(plaintext);
    }

    return results;
  };
}
