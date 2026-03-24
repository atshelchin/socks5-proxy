import { test, expect, describe } from "bun:test";
import {
  uuidToBytes,
  computeCmdKey,
  vmessKDF,
  generateAuthID,
  crc32,
  fnv1a32,
  aeadSeal,
  aeadOpen,
  deriveRequestBodyKeyIV,
  deriveResponseBodyKeyIV,
} from "./crypto";
import { createChunkEncoder, createChunkDecoder } from "./chunk";
import { createVMessSession, buildRequest } from "./vmess";
import { createHash, createHmac, createCipheriv, createDecipheriv } from "node:crypto";

// ============================================================
// Crypto primitives
// ============================================================

describe("uuidToBytes", () => {
  test("parses standard UUID to 16 bytes", () => {
    const bytes = uuidToBytes("1afc1706-34ff-41b1-9dc8-b3ab9ecb6e00");
    expect(bytes.length).toBe(16);
    expect(bytes.toString("hex")).toBe("1afc170634ff41b19dc8b3ab9ecb6e00");
  });
});

describe("computeCmdKey", () => {
  test("MD5(uuid + salt) produces 16 bytes", () => {
    const uuidBytes = uuidToBytes("1afc1706-34ff-41b1-9dc8-b3ab9ecb6e00");
    const cmdKey = computeCmdKey(uuidBytes);
    expect(cmdKey.length).toBe(16);
    // Verify manually: MD5(uuid_bytes + "c48619fe-8f02-49e0-b9e9-edf763e17e21")
    const expected = createHash("md5")
      .update(uuidBytes)
      .update("c48619fe-8f02-49e0-b9e9-edf763e17e21")
      .digest();
    expect(cmdKey.equals(expected)).toBe(true);
  });
});

describe("CRC32", () => {
  test("standard test vector", () => {
    expect(crc32(Buffer.from("123456789"))).toBe(0xcbf43926);
  });

  test("empty input", () => {
    expect(crc32(Buffer.alloc(0))).toBe(0x00000000);
  });
});

describe("FNV-1a 32-bit", () => {
  test("known test vector", () => {
    expect(fnv1a32(Buffer.from("hello"))).toBe(0x4f9f2cab);
  });

  test("empty input", () => {
    expect(fnv1a32(Buffer.alloc(0))).toBe(0x811c9dc5);
  });
});

// ============================================================
// KDF
// ============================================================

describe("vmessKDF", () => {
  const testKey = Buffer.from("testkey");

  test("base case equals HMAC-SHA256 with salt key", () => {
    const result = vmessKDF(testKey);
    const expected = createHmac("sha256", "VMess AEAD KDF").update(testKey).digest();
    expect(result.equals(expected)).toBe(true);
  });

  test("with 1 path produces different result from simple chain", () => {
    const result = vmessKDF(testKey, "path1");
    // Simple (wrong) chain:
    const simpleChain = createHmac(
      "sha256",
      createHmac("sha256", "path1").update("VMess AEAD KDF").digest(),
    ).update(testKey).digest();
    // Nested HMAC should differ from simple chain
    expect(result.equals(simpleChain)).toBe(false);
  });

  test("deterministic", () => {
    const a = vmessKDF(testKey, "p1", Buffer.from("p2"));
    const b = vmessKDF(testKey, "p1", Buffer.from("p2"));
    expect(a.equals(b)).toBe(true);
  });

  test("different paths produce different results", () => {
    const a = vmessKDF(testKey, "path_a");
    const b = vmessKDF(testKey, "path_b");
    expect(a.equals(b)).toBe(false);
  });

  test("output is 32 bytes (SHA-256)", () => {
    expect(vmessKDF(testKey).length).toBe(32);
    expect(vmessKDF(testKey, "p1").length).toBe(32);
    expect(vmessKDF(testKey, "p1", "p2", "p3").length).toBe(32);
  });

  test("matches reference implementation", async () => {
    // Import reference KDF
    const { vmessKdf: refKdf } = await import(
      "/Volumes/data/workspace/tradingbot-server-share/dd/vmess/crypto.ts"
    );
    const key = Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex");
    const path1 = "VMess Header AEAD Key_Length";
    const path2 = Buffer.from("aabbccddeeff0011aabbccddeeff0011", "hex");
    const path3 = Buffer.from("1122334455667788", "hex");

    const myResult = vmessKDF(key, path1, path2, path3);
    const refResult = await refKdf(
      new Uint8Array(key),
      new TextEncoder().encode(path1),
      new Uint8Array(path2),
      new Uint8Array(path3),
    );
    expect(myResult.equals(Buffer.from(refResult))).toBe(true);
  });
});

// ============================================================
// AEAD seal/open
// ============================================================

describe("AEAD", () => {
  const key16 = Buffer.alloc(16, 0x03);
  const nonce12 = Buffer.alloc(12, 0x04);
  const plaintext = Buffer.from("hello vmess world");
  const aad = Buffer.from("additional-data");

  test("AES-128-GCM roundtrip", () => {
    const sealed = aeadSeal("aes-128-gcm", key16, nonce12, plaintext, aad);
    expect(sealed.length).toBe(plaintext.length + 16); // +tag
    const opened = aeadOpen("aes-128-gcm", key16, nonce12, sealed, aad);
    expect(opened.equals(plaintext)).toBe(true);
  });

  test("AES-128-GCM without AAD", () => {
    const sealed = aeadSeal("aes-128-gcm", key16, nonce12, plaintext);
    const opened = aeadOpen("aes-128-gcm", key16, nonce12, sealed);
    expect(opened.equals(plaintext)).toBe(true);
  });

  test("wrong key fails", () => {
    const sealed = aeadSeal("aes-128-gcm", key16, nonce12, plaintext, aad);
    const wrongKey = Buffer.alloc(16, 0xff);
    expect(() => aeadOpen("aes-128-gcm", wrongKey, nonce12, sealed, aad)).toThrow();
  });

  test("wrong AAD fails", () => {
    const sealed = aeadSeal("aes-128-gcm", key16, nonce12, plaintext, aad);
    expect(() => aeadOpen("aes-128-gcm", key16, nonce12, sealed, Buffer.from("wrong"))).toThrow();
  });
});

// ============================================================
// AuthID
// ============================================================

describe("generateAuthID", () => {
  test("produces 16 bytes", () => {
    const cmdKey = Buffer.alloc(16, 0xaa);
    const authID = generateAuthID(cmdKey, Math.floor(Date.now() / 1000));
    expect(authID.length).toBe(16);
  });

  test("decrypts to valid timestamp + CRC32", () => {
    const cmdKey = Buffer.alloc(16, 0xaa);
    const timestamp = Math.floor(Date.now() / 1000);
    const authID = generateAuthID(cmdKey, timestamp);

    // Decrypt with same derived key
    const aesKey = vmessKDF(cmdKey, "AES Auth ID Encryption").subarray(0, 16);
    const decipher = createDecipheriv("aes-128-ecb", aesKey, null);
    decipher.setAutoPadding(false);
    const decrypted = Buffer.concat([decipher.update(authID), decipher.final()]);

    // Check timestamp
    const ts = Number(decrypted.readBigUInt64BE(0));
    expect(ts).toBe(timestamp);

    // Check CRC32
    const expectedCRC = crc32(decrypted.subarray(0, 12));
    const actualCRC = decrypted.readUInt32BE(12);
    expect(actualCRC).toBe(expectedCRC);
  });

  test("different timestamps produce different AuthIDs", () => {
    const cmdKey = Buffer.alloc(16, 0xaa);
    const a = generateAuthID(cmdKey, 1000000);
    const b = generateAuthID(cmdKey, 1000001);
    expect(a.equals(b)).toBe(false);
  });
});

// ============================================================
// Key derivation
// ============================================================

describe("body key derivation", () => {
  const dataKey = Buffer.from(crypto.getRandomValues(new Uint8Array(16)));
  const dataIV = Buffer.from(crypto.getRandomValues(new Uint8Array(16)));

  test("request body key is SHA256(dataKey)[:16] for GCM", () => {
    const { key, iv } = deriveRequestBodyKeyIV(dataKey, dataIV, "aes-128-gcm");
    const expectedKey = createHash("sha256").update(dataKey).digest().subarray(0, 16);
    const expectedIV = createHash("sha256").update(dataIV).digest().subarray(0, 16);
    expect(key.equals(expectedKey)).toBe(true);
    expect(iv.equals(expectedIV)).toBe(true);
  });

  test("response body key is SHA256(requestBodyKey)[:16] for GCM", () => {
    const { key: reqKey, iv: reqIV } = deriveRequestBodyKeyIV(dataKey, dataIV, "aes-128-gcm");
    const { key: respKey, iv: respIV } = deriveResponseBodyKeyIV(reqKey, reqIV, "aes-128-gcm");
    const expectedKey = createHash("sha256").update(reqKey).digest().subarray(0, 16);
    const expectedIV = createHash("sha256").update(reqIV).digest().subarray(0, 16);
    expect(respKey.equals(expectedKey)).toBe(true);
    expect(respIV.equals(expectedIV)).toBe(true);
  });

  test("request and response keys are different", () => {
    const { key: reqKey } = deriveRequestBodyKeyIV(dataKey, dataIV, "aes-128-gcm");
    const { key: respKey } = deriveResponseBodyKeyIV(reqKey, dataIV, "aes-128-gcm");
    expect(reqKey.equals(respKey)).toBe(false);
  });
});

// ============================================================
// Chunk encoder/decoder
// ============================================================

describe("chunk encoder/decoder", () => {
  const key = Buffer.alloc(16, 0x05);
  const iv = Buffer.alloc(16, 0x06);

  test("roundtrip small data", () => {
    const encoder = createChunkEncoder(key, iv, "aes-128-gcm");
    const decoder = createChunkDecoder(key, iv, "aes-128-gcm");

    const plain = Buffer.from("Hello, VMess!");
    const encoded = encoder(plain);
    expect(encoded.length).toBeGreaterThan(plain.length);

    const decoded = decoder(encoded);
    expect(decoded.length).toBe(1);
    expect(decoded[0]!.equals(plain)).toBe(true);
  });

  test("roundtrip large data (multiple chunks)", () => {
    const encoder = createChunkEncoder(key, iv, "aes-128-gcm");
    const decoder = createChunkDecoder(key, iv, "aes-128-gcm");

    // 32KB — will split into 2 chunks (max 16KB each)
    const plain = Buffer.alloc(32 * 1024, 0x41);
    const encoded = encoder(plain);

    const decoded = decoder(encoded);
    expect(decoded.length).toBe(2);
    const reassembled = Buffer.concat(decoded);
    expect(reassembled.equals(plain)).toBe(true);
  });

  test("handles fragmented input", () => {
    const encoder = createChunkEncoder(key, iv, "aes-128-gcm");
    const decoder = createChunkDecoder(key, iv, "aes-128-gcm");

    const plain = Buffer.from("fragmented data test");
    const encoded = encoder(plain);

    // Feed byte by byte
    const results: Buffer[] = [];
    for (let i = 0; i < encoded.length; i++) {
      const chunks = decoder(encoded.subarray(i, i + 1));
      results.push(...chunks);
    }
    expect(results.length).toBe(1);
    expect(results[0]!.equals(plain)).toBe(true);
  });

  test("multiple encodes use incrementing nonces", () => {
    const encoder = createChunkEncoder(key, iv, "aes-128-gcm");
    const decoder = createChunkDecoder(key, iv, "aes-128-gcm");

    const msg1 = Buffer.from("message one");
    const msg2 = Buffer.from("message two");

    const enc1 = encoder(msg1);
    const enc2 = encoder(msg2);

    // Decode in order
    const dec1 = decoder(enc1);
    const dec2 = decoder(enc2);
    expect(dec1[0]!.equals(msg1)).toBe(true);
    expect(dec2[0]!.equals(msg2)).toBe(true);
  });

  test("wrong key fails to decode", () => {
    const encoder = createChunkEncoder(key, iv, "aes-128-gcm");
    const wrongDecoder = createChunkDecoder(Buffer.alloc(16, 0xff), iv, "aes-128-gcm");

    const encoded = encoder(Buffer.from("secret"));
    expect(() => wrongDecoder(encoded)).toThrow();
  });
});

// ============================================================
// Request header building
// ============================================================

describe("buildRequest", () => {
  const session = createVMessSession({
    address: "test.example.com",
    port: 443,
    uuid: "c831391d-9878-b879-1234-acda48b30811",
    security: "aes-128-gcm",
  });

  test("produces valid header buffer", () => {
    const req = buildRequest(session, "httpbin.org", 80);

    // Header structure: AuthID(16) + encLen(18) + nonce(8) + encPayload(var)
    expect(req.headerBuf.length).toBeGreaterThan(42);
    expect(req.requestBodyKey.length).toBe(16);
    expect(req.requestBodyIV.length).toBe(16);
    expect(req.responseBodyKey.length).toBe(16);
    expect(req.responseBodyIV.length).toBe(16);
    expect(req.responseAuthV).toBeGreaterThanOrEqual(0);
    expect(req.responseAuthV).toBeLessThan(256);
  });

  test("header can be decrypted", () => {
    const req = buildRequest(session, "httpbin.org", 80);
    const hdr = req.headerBuf;

    const authID = hdr.subarray(0, 16);
    const encLen = hdr.subarray(16, 34);
    const connNonce = hdr.subarray(34, 42);
    const encPayload = hdr.subarray(42);

    // Decrypt length
    const lenKey = vmessKDF(session.cmdKey, "VMess Header AEAD Key_Length", authID, connNonce).subarray(0, 16);
    const lenIV = vmessKDF(session.cmdKey, "VMess Header AEAD Nonce_Length", authID, connNonce).subarray(0, 12);
    const lenPlain = aeadOpen("aes-128-gcm", lenKey, lenIV, encLen, authID);
    const instrLen = lenPlain.readUInt16BE(0);
    expect(instrLen).toBeGreaterThan(40);

    // Decrypt payload
    const payKey = vmessKDF(session.cmdKey, "VMess Header AEAD Key", authID, connNonce).subarray(0, 16);
    const payIV = vmessKDF(session.cmdKey, "VMess Header AEAD Nonce", authID, connNonce).subarray(0, 12);
    const instrPlain = aeadOpen("aes-128-gcm", payKey, payIV, encPayload, authID);
    expect(instrPlain.length).toBe(instrLen);

    // Parse instruction
    expect(instrPlain[0]).toBe(0x01); // version
    // Bytes 1-16: IV, 17-32: Key (skip)
    expect(instrPlain[34]).toBe(0x01); // option: chunk stream
    expect(instrPlain[37]).toBe(0x01); // CMD: TCP

    const port = instrPlain.readUInt16BE(38);
    expect(port).toBe(80);

    expect(instrPlain[40]).toBe(0x02); // addr type: domain
    const domainLen = instrPlain[41]!;
    const domain = instrPlain.subarray(42, 42 + domainLen).toString();
    expect(domain).toBe("httpbin.org");
  });

  test("header decodes with reference implementation", async () => {
    const { decodeRequestHeaderAead } = await import(
      "/Volumes/data/workspace/tradingbot-server-share/dd/vmess/decoder.ts"
    );

    const req = buildRequest(session, "example.com", 443);
    const decoded = await decodeRequestHeaderAead(
      new Uint8Array(req.headerBuf),
      "c831391d-9878-b879-1234-acda48b30811",
      Math.floor(Date.now() / 1000),
    );

    expect(decoded.version).toBe(1);
    expect(decoded.address).toBe("example.com");
    expect(decoded.port).toBe(443);
    expect(decoded.security).toBe(3); // AES-128-GCM
    expect(decoded.command).toBe(1); // TCP
    expect(decoded.responseV).toBe(req.responseAuthV);
  });

  test("different targets produce different headers", () => {
    const a = buildRequest(session, "a.com", 80);
    const b = buildRequest(session, "b.com", 443);
    expect(a.headerBuf.equals(b.headerBuf)).toBe(false);
  });

  test("IPv4 target", () => {
    const req = buildRequest(session, "1.2.3.4", 8080);
    // Should not throw, header should be valid
    expect(req.headerBuf.length).toBeGreaterThan(42);
  });
});

// ============================================================
// End-to-end: encode request, simulate server decode
// ============================================================

describe("end-to-end request encoding", () => {
  const session = createVMessSession({
    address: "test.example.com",
    port: 443,
    uuid: "c831391d-9878-b879-1234-acda48b30811",
    security: "aes-128-gcm",
  });

  test("server can decrypt data chunks", async () => {
    const req = buildRequest(session, "httpbin.org", 80);
    const encoder = createChunkEncoder(req.requestBodyKey, req.requestBodyIV, "aes-128-gcm");

    const httpRequest = Buffer.from("GET /get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n");
    const encrypted = encoder(httpRequest);

    // Server-side: use same key/IV to decrypt
    const decoder = createChunkDecoder(req.requestBodyKey, req.requestBodyIV, "aes-128-gcm");
    const decrypted = decoder(encrypted);

    expect(decrypted.length).toBe(1);
    expect(decrypted[0]!.equals(httpRequest)).toBe(true);
  });

  test("simulated response can be decoded", () => {
    const req = buildRequest(session, "httpbin.org", 80);

    // Simulate server building response header
    const respLenKey = vmessKDF(req.responseBodyKey, "AEAD Resp Header Len Key").subarray(0, 16);
    const respLenIV = vmessKDF(req.responseBodyIV, "AEAD Resp Header Len IV").subarray(0, 12);
    const respHdrKey = vmessKDF(req.responseBodyKey, "AEAD Resp Header Key").subarray(0, 16);
    const respHdrIV = vmessKDF(req.responseBodyIV, "AEAD Resp Header IV").subarray(0, 12);

    // Response header plaintext: [responseAuthV, option=0, cmd=0, cmdLen=0]
    const respHdrPlain = Buffer.from([req.responseAuthV, 0x00, 0x00, 0x00]);
    const lenBuf = Buffer.alloc(2);
    lenBuf.writeUInt16BE(respHdrPlain.length, 0);

    const encLen = aeadSeal("aes-128-gcm", respLenKey, respLenIV, lenBuf);
    const encHdr = aeadSeal("aes-128-gcm", respHdrKey, respHdrIV, respHdrPlain);

    // Simulate server building response data
    const responseEncoder = createChunkEncoder(req.responseBodyKey, req.responseBodyIV, "aes-128-gcm");
    const responseBody = Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
    const encBody = responseEncoder(responseBody);

    // Client decodes response
    const fullResponse = Buffer.concat([encLen, encHdr, encBody]);

    // Decrypt length
    const decLen = aeadOpen("aes-128-gcm", respLenKey, respLenIV, fullResponse.subarray(0, 18));
    const hdrLen = decLen.readUInt16BE(0);
    expect(hdrLen).toBe(4);

    // Decrypt header
    const decHdr = aeadOpen("aes-128-gcm", respHdrKey, respHdrIV, fullResponse.subarray(18, 38));
    expect(decHdr[0]).toBe(req.responseAuthV);

    // Decrypt body
    const responseDecoder = createChunkDecoder(req.responseBodyKey, req.responseBodyIV, "aes-128-gcm");
    const bodyChunks = responseDecoder(fullResponse.subarray(38));
    expect(bodyChunks.length).toBe(1);
    expect(bodyChunks[0]!.equals(responseBody)).toBe(true);
  });
});
