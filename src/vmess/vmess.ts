/**
 * VMess AEAD client implementation (alterId=0)
 */

import { type Socket } from "bun";
import { STATE_FORWARDING } from "../socks5";
import {
  uuidToBytes,
  computeCmdKey,
  vmessKDF,
  generateAuthID,
  fnv1a32,
  aeadSeal,
  aeadOpen,
  deriveRequestBodyKeyIV,
  deriveResponseBodyKeyIV,
} from "./crypto";
import { createChunkEncoder, createChunkDecoder } from "./chunk";

// --- Config ---

export interface VMessUpstream {
  address: string;
  port: number;
  uuid: string;
  security: "aes-128-gcm" | "chacha20-poly1305" | "none";
  network?: "tcp" | "ws";  // default: tcp
  tls?: boolean;            // default: false
  wsPath?: string;          // WebSocket path, e.g. "/baba"
  wsHost?: string;          // WebSocket Host header
}

// --- Pre-computed session keys (compute once at startup) ---

export interface VMessSession {
  uuidBytes: Buffer;
  cmdKey: Buffer;
  config: VMessUpstream;
}

export function createVMessSession(config: VMessUpstream): VMessSession {
  const uuidBytes = uuidToBytes(config.uuid);
  const cmdKey = computeCmdKey(uuidBytes);
  return { uuidBytes, cmdKey, config };
}

// --- Security constants ---

const SECURITY_AES_128_GCM = 0x03;
const SECURITY_CHACHA20_POLY1305 = 0x04;
const SECURITY_NONE = 0x05;

function securityByte(s: VMessUpstream["security"]): number {
  switch (s) {
    case "aes-128-gcm": return SECURITY_AES_128_GCM;
    case "chacha20-poly1305": return SECURITY_CHACHA20_POLY1305;
    case "none": return SECURITY_NONE;
  }
}

function aeadAlgo(s: VMessUpstream["security"]): "aes-128-gcm" | "chacha20-poly1305" {
  return s === "chacha20-poly1305" ? "chacha20-poly1305" : "aes-128-gcm";
}

// --- Build request header ---

interface RequestResult {
  headerBuf: Buffer;
  requestBodyKey: Buffer;
  requestBodyIV: Buffer;
  responseBodyKey: Buffer;
  responseBodyIV: Buffer;
  responseAuthV: number;
}

export function buildRequest(
  session: VMessSession,
  targetHost: string,
  targetPort: number,
): RequestResult {
  const { cmdKey, config } = session;
  const timestamp = Math.floor(Date.now() / 1000);

  // Random keys for this connection
  const dataKey = Buffer.from(crypto.getRandomValues(new Uint8Array(16)));
  const dataIV = Buffer.from(crypto.getRandomValues(new Uint8Array(16)));
  const responseAuthV = crypto.getRandomValues(new Uint8Array(1))[0]!;

  // --- Build instruction payload ---
  const sec = config.security;
  const secByte = securityByte(sec);

  // Option: 0x01 = chunk stream (simplest format, no masking)
  const option = 0x01;
  const paddingLen = 0; // no padding for speed

  // Address encoding
  let addrType: number;
  let addrBuf: Buffer;

  // Check if IPv4
  const ipv4Match = targetHost.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4Match) {
    addrType = 0x01;
    addrBuf = Buffer.from([
      parseInt(ipv4Match[1]!),
      parseInt(ipv4Match[2]!),
      parseInt(ipv4Match[3]!),
      parseInt(ipv4Match[4]!),
    ]);
  } else if (targetHost.includes(":")) {
    // IPv6
    addrType = 0x03;
    const parts = targetHost.split(":");
    addrBuf = Buffer.alloc(16);
    for (let i = 0; i < 8; i++) {
      const val = parseInt(parts[i] || "0", 16);
      addrBuf.writeUInt16BE(val, i * 2);
    }
  } else {
    // Domain
    addrType = 0x02;
    const domainBuf = Buffer.from(targetHost);
    addrBuf = Buffer.alloc(1 + domainBuf.length);
    addrBuf[0] = domainBuf.length;
    domainBuf.copy(addrBuf, 1);
  }

  // Instruction: Ver(1) + IV(16) + Key(16) + V(1) + Opt(1) + PaddingSec(1) + Rsv(1) + Cmd(1) + Port(2) + AddrType(1) + Addr(var) + Padding(var) + F(4)
  const instrLen = 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + addrBuf.length + paddingLen;
  const instruction = Buffer.alloc(instrLen + 4); // +4 for FNV1a

  let offset = 0;
  instruction[offset++] = 0x01; // Version
  dataIV.copy(instruction, offset); offset += 16;
  dataKey.copy(instruction, offset); offset += 16;
  instruction[offset++] = responseAuthV;
  instruction[offset++] = option;
  instruction[offset++] = (paddingLen << 4) | secByte;
  instruction[offset++] = 0x00; // Reserved
  instruction[offset++] = 0x01; // CMD: TCP
  instruction.writeUInt16BE(targetPort, offset); offset += 2;
  instruction[offset++] = addrType;
  addrBuf.copy(instruction, offset); offset += addrBuf.length;
  // padding (0 bytes)

  // FNV1a of everything before it
  const fnv = fnv1a32(instruction.subarray(0, offset));
  instruction.writeUInt32BE(fnv, offset);

  // --- Generate AuthID ---
  const authID = generateAuthID(cmdKey, timestamp);

  // --- Connection nonce ---
  const connectionNonce = Buffer.from(crypto.getRandomValues(new Uint8Array(8)));

  // --- Derive header encryption keys ---
  const headerLengthKey = vmessKDF(
    cmdKey,
    "VMess Header AEAD Key_Length",
    authID,
    connectionNonce,
  ).subarray(0, 16);

  const headerLengthIV = vmessKDF(
    cmdKey,
    "VMess Header AEAD Nonce_Length",
    authID,
    connectionNonce,
  ).subarray(0, 12);

  const headerPayloadKey = vmessKDF(
    cmdKey,
    "VMess Header AEAD Key",
    authID,
    connectionNonce,
  ).subarray(0, 16);

  const headerPayloadIV = vmessKDF(
    cmdKey,
    "VMess Header AEAD Nonce",
    authID,
    connectionNonce,
  ).subarray(0, 12);

  // --- Encrypt header ---
  const instrLenBuf = Buffer.alloc(2);
  instrLenBuf.writeUInt16BE(instruction.length, 0);

  const encryptedLength = aeadSeal("aes-128-gcm", headerLengthKey, headerLengthIV, instrLenBuf, authID);
  const encryptedPayload = aeadSeal("aes-128-gcm", headerPayloadKey, headerPayloadIV, instruction, authID);

  // Assemble: AuthID(16) + encryptedLength(18) + connectionNonce(8) + encryptedPayload(var)
  const headerBuf = Buffer.concat([authID, encryptedLength, connectionNonce, encryptedPayload]);

  // --- Derive body keys ---
  const algo = aeadAlgo(sec);
  const { key: requestBodyKey, iv: requestBodyIV } = deriveRequestBodyKeyIV(dataKey, dataIV, algo);
  const { key: responseBodyKey, iv: responseBodyIV } = deriveResponseBodyKeyIV(requestBodyKey, requestBodyIV, algo);

  return {
    headerBuf,
    requestBodyKey,
    requestBodyIV,
    responseBodyKey,
    responseBodyIV,
    responseAuthV,
  };
}

// --- VMess connection ---

interface VMessClientData {
  client: Socket<any>;
  encoder: (data: Buffer) => Buffer;
  decoder: (data: Buffer) => Buffer[];
  responseHeaderParsed: boolean;
  responseHeaderBuf: Buffer;
  responseAuthV: number;
  responseBodyKey: Buffer;
  responseBodyIV: Buffer;
  algorithm: "aes-128-gcm" | "chacha20-poly1305";
}

export function connectVMess(
  clientSocket: Socket<any>,
  targetHost: string,
  targetPort: number,
  session: VMessSession,
  onConnected?: () => void,
  onError?: () => void,
) {
  const { config } = session;

  if (config.network === "ws") {
    connectVMessWS(clientSocket, targetHost, targetPort, session, onConnected, onError);
  } else {
    connectVMessTCP(clientSocket, targetHost, targetPort, session, onConnected, onError);
  }
}

// --- Response data handler (shared between TCP and WS) ---

function createResponseHandler(
  clientSocket: Socket<any>,
  req: RequestResult,
  algo: "aes-128-gcm" | "chacha20-poly1305",
) {
  let decoder: ReturnType<typeof createChunkDecoder> | null = null;
  let responseHeaderParsed = false;
  let responseHeaderBuf = Buffer.alloc(0);
  const RESP_HDR_LEN_SIZE = 18;

  const respLenKey = vmessKDF(req.responseBodyKey, "AEAD Resp Header Len Key").subarray(0, 16);
  const respLenIV = vmessKDF(req.responseBodyIV, "AEAD Resp Header Len IV").subarray(0, 12);
  const respHdrKey = vmessKDF(req.responseBodyKey, "AEAD Resp Header Key").subarray(0, 16);
  const respHdrIV = vmessKDF(req.responseBodyIV, "AEAD Resp Header IV").subarray(0, 12);

  return function handleData(data: Buffer): boolean {
    if (!responseHeaderParsed) {
      responseHeaderBuf = responseHeaderBuf.length === 0
        ? Buffer.from(data)
        : Buffer.concat([responseHeaderBuf, data]);

      if (responseHeaderBuf.length < RESP_HDR_LEN_SIZE) return true;

      try {
        const lenPlain = aeadOpen(
          "aes-128-gcm", respLenKey, respLenIV,
          responseHeaderBuf.subarray(0, RESP_HDR_LEN_SIZE),
        );
        const hdrPayloadLen = lenPlain.readUInt16BE(0);
        const totalHdrSize = RESP_HDR_LEN_SIZE + hdrPayloadLen + 16;

        if (responseHeaderBuf.length < totalHdrSize) return true;

        const hdrPlain = aeadOpen(
          "aes-128-gcm", respHdrKey, respHdrIV,
          responseHeaderBuf.subarray(RESP_HDR_LEN_SIZE, totalHdrSize),
        );

        if (hdrPlain[0] !== req.responseAuthV) return false;

        responseHeaderParsed = true;
        decoder = createChunkDecoder(req.responseBodyKey, req.responseBodyIV, algo);

        const remaining = responseHeaderBuf.subarray(totalHdrSize);
        responseHeaderBuf = Buffer.alloc(0);

        if (remaining.length > 0) {
          const chunks = decoder(remaining);
          for (const chunk of chunks) clientSocket.write(chunk);
        }
      } catch {
        return false;
      }
      return true;
    }

    const chunks = decoder!(data);
    for (const chunk of chunks) clientSocket.write(chunk);
    return true;
  };
}

// --- TCP transport ---

function connectVMessTCP(
  clientSocket: Socket<any>,
  targetHost: string,
  targetPort: number,
  session: VMessSession,
  onConnected?: () => void,
  onError?: () => void,
) {
  const algo = aeadAlgo(session.config.security);
  const req = buildRequest(session, targetHost, targetPort);
  const encoder = createChunkEncoder(req.requestBodyKey, req.requestBodyIV, algo);
  const handleResponse = createResponseHandler(clientSocket, req, algo);

  Bun.connect<VMessClientData>({
    hostname: session.config.address,
    port: session.config.port,
    socket: {
      open(remote) {
        remote.write(req.headerBuf);
        clientSocket.data.remote = remote;
        clientSocket.data.state = STATE_FORWARDING;
        clientSocket.data.encoder = encoder;
        onConnected?.();
        if (clientSocket.data.buffer) {
          remote.write(encoder(Buffer.from(clientSocket.data.buffer)));
          clientSocket.data.buffer = null;
        }
      },
      data(remote, data) {
        if (!handleResponse(Buffer.from(data))) {
          clientSocket.end();
          remote.end();
        }
      },
      close() { clientSocket.end(); },
      error() { clientSocket.end(); },
      connectError() { onError?.(); clientSocket.end(); },
      drain() { clientSocket.resume(); },
    },
    data: {} as VMessClientData,
  }).catch(() => { onError?.(); clientSocket.end(); });
}

// --- WebSocket transport ---

function connectVMessWS(
  clientSocket: Socket<any>,
  targetHost: string,
  targetPort: number,
  session: VMessSession,
  onConnected?: () => void,
  onError?: () => void,
) {
  const algo = aeadAlgo(session.config.security);
  const req = buildRequest(session, targetHost, targetPort);
  const encoder = createChunkEncoder(req.requestBodyKey, req.requestBodyIV, algo);
  const handleResponse = createResponseHandler(clientSocket, req, algo);

  const protocol = session.config.tls ? "wss" : "ws";
  const host = session.config.wsHost || session.config.address;
  const path = session.config.wsPath || "/";
  const port = session.config.port;
  const wsUrl = `${protocol}://${host}:${port}${path}`;

  const ws = new WebSocket(wsUrl);
  ws.binaryType = "arraybuffer";

  // Wrap WebSocket as a writable interface for the proxy
  const wsWriter = {
    write(data: Buffer | Uint8Array): number {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
        return data.length;
      }
      return 0;
    },
    end() { ws.close(); },
    pause() {},
    resume() {},
  };

  ws.onopen = () => {
    // Send VMess header + any buffered data
    const parts: Buffer[] = [req.headerBuf];
    if (clientSocket.data.buffer) {
      parts.push(encoder(Buffer.from(clientSocket.data.buffer)));
      clientSocket.data.buffer = null;
    }
    ws.send(Buffer.concat(parts));

    clientSocket.data.remote = wsWriter as any;
    clientSocket.data.state = STATE_FORWARDING;
    clientSocket.data.encoder = encoder;
    onConnected?.();
  };

  ws.onmessage = (event) => {
    const data = Buffer.from(event.data as ArrayBuffer);
    if (!handleResponse(data)) {
      clientSocket.end();
      ws.close();
    }
  };

  ws.onclose = () => { clientSocket.end(); };
  ws.onerror = () => { onError?.(); clientSocket.end(); };
}
