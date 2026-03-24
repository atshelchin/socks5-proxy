/**
 * End-to-end test: local VMess server ↔ our proxy client
 */

import { test, expect, describe, beforeAll, afterAll } from "bun:test";
import { createServer } from "../socks5";
import { type TCPSocketListener } from "bun";
import {
  vmessKDF, aeadOpen, aeadSeal,
  deriveRequestBodyKeyIV, deriveResponseBodyKeyIV,
} from "./crypto";
import { createChunkEncoder, createChunkDecoder } from "./chunk";
import { createDecipheriv, createHash } from "node:crypto";

const UUID = "11111111-2222-3333-4444-555555555555";
const VP = 16080; // VMess
const PP = 16081; // Proxy
const TP = 16082; // Target

const cmdKey = createHash("md5")
  .update(Buffer.from(UUID.replace(/-/g, ""), "hex"))
  .update("c48619fe-8f02-49e0-b9e9-edf763e17e21")
  .digest();

// --- Mini VMess AEAD server ---

function startVMessServer() {
  return Bun.listen({
    hostname: "127.0.0.1",
    port: VP,
    socket: {
      open(s) {
        s.data = { parsed: false, decoder: null, respKey: null, respIV: null, rv: 0, th: "", tp: 0 };
      },
      data(s, rawData) {
        const d = Buffer.from(rawData);
        const st = s.data as any;

        if (!st.parsed) {
          try {
            const aid = d.subarray(0, 16), cn = d.subarray(34, 42);
            const ak = vmessKDF(cmdKey, "AES Auth ID Encryption").subarray(0, 16);
            const dc = createDecipheriv("aes-128-ecb", ak, null);
            dc.setAutoPadding(false);
            Buffer.concat([dc.update(aid), dc.final()]);

            const lk = vmessKDF(cmdKey, "VMess Header AEAD Key_Length", aid, cn).subarray(0, 16);
            const li = vmessKDF(cmdKey, "VMess Header AEAD Nonce_Length", aid, cn).subarray(0, 12);
            const il = aeadOpen("aes-128-gcm", lk, li, d.subarray(16, 34), aid).readUInt16BE(0);

            const pk = vmessKDF(cmdKey, "VMess Header AEAD Key", aid, cn).subarray(0, 16);
            const pi = vmessKDF(cmdKey, "VMess Header AEAD Nonce", aid, cn).subarray(0, 12);
            const ins = aeadOpen("aes-128-gcm", pk, pi, d.subarray(42, 42 + il + 16), aid);

            let o = 1;
            const iv = ins.subarray(o, o + 16); o += 16;
            const ky = ins.subarray(o, o + 16); o += 16;
            st.rv = ins[o++]!; o += 3; o++;
            st.tp = ins.readUInt16BE(o); o += 2;
            const at = ins[o++]!;
            if (at === 1) { st.th = `${ins[o]}.${ins[o! + 1]}.${ins[o! + 2]}.${ins[o! + 3]}`; o += 4; }
            else if (at === 2) { const dl = ins[o++]!; st.th = ins.subarray(o, o + dl).toString(); o += dl; }

            // Server uses reqKey/IV from instruction directly (already SHA256'd by client)
            const bk = Buffer.from(ky);
            const bi = Buffer.from(iv);
            const { key: rk, iv: ri } = deriveResponseBodyKeyIV(bk, bi, "aes-128-gcm");
            st.respKey = rk; st.respIV = ri;
            st.decoder = createChunkDecoder(bk, bi, "aes-128-gcm");
            st.parsed = true;

            const ds = 42 + il + 16;
            if (d.length > ds) {
              const ch = st.decoder(d.subarray(ds));
              if (ch.length > 0) forward(s, st, Buffer.concat(ch));
            }
          } catch { s.end(); }
        } else {
          try {
            const ch = st.decoder(d);
            if (ch.length > 0) forward(s, st, Buffer.concat(ch));
          } catch { s.end(); }
        }
      },
      close() {}, error() {},
    },
    data: {},
  });
}

function forward(vs: any, st: any, data: Buffer) {
  Bun.connect({
    hostname: st.th, port: st.tp,
    socket: {
      open(t) { t.write(data); },
      data(t, rd) {
        const buf = Buffer.from(rd);
        const rlk = vmessKDF(st.respKey, "AEAD Resp Header Len Key").subarray(0, 16);
        const rli = vmessKDF(st.respIV, "AEAD Resp Header Len IV").subarray(0, 12);
        const rhk = vmessKDF(st.respKey, "AEAD Resp Header Key").subarray(0, 16);
        const rhi = vmessKDF(st.respIV, "AEAD Resp Header IV").subarray(0, 12);
        const lb = Buffer.alloc(2); lb.writeUInt16BE(4, 0);
        vs.write(Buffer.concat([
          aeadSeal("aes-128-gcm", rlk, rli, lb),
          aeadSeal("aes-128-gcm", rhk, rhi, Buffer.from([st.rv, 0, 0, 0])),
          createChunkEncoder(st.respKey, st.respIV, "aes-128-gcm")(buf),
        ]));
      },
      close() { vs.end(); }, error() { vs.end(); },
    }, data: {},
  });
}

// --- Target HTTP server ---

function startTarget() {
  return Bun.listen({
    hostname: "127.0.0.1", port: TP,
    socket: {
      data(s) {
        s.write("HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nHello VMess!\n");
        s.end();
      },
      open() {}, close() {}, error() {},
    }, data: {},
  });
}

// --- Setup ---

let vmessServer: ReturnType<typeof startVMessServer>;
let targetServer: ReturnType<typeof startTarget>;
let proxyServer: TCPSocketListener<unknown>;

beforeAll(() => {
  vmessServer = startVMessServer();
  targetServer = startTarget();
  proxyServer = createServer({
    port: PP, host: "127.0.0.1",
    vmess: { address: "127.0.0.1", port: VP, uuid: UUID, security: "aes-128-gcm" },
  });
});

afterAll(() => {
  vmessServer.stop(true);
  targetServer.stop(true);
  proxyServer.stop(true);
});

// --- Tests ---

async function socks5Request(): Promise<string> {
  return new Promise((resolve, reject) => {
    let step = 0, response = "";
    Bun.connect({
      hostname: "127.0.0.1", port: PP,
      socket: {
        open(s) { s.write(Buffer.from([0x05, 0x01, 0x00])); },
        data(s, data) {
          const b = Buffer.from(data);
          if (step === 0) {
            s.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, (TP >> 8) & 0xff, TP & 0xff]));
            step = 1;
          } else if (step === 1) {
            s.write(Buffer.from("GET /test HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"));
            step = 2;
          } else {
            response += b.toString();
          }
        },
        close() { resolve(response); },
        error(s, e) { reject(e); },
      }, data: {},
    });
    setTimeout(() => resolve(response), 5000);
  });
}

async function httpConnectRequest(): Promise<string> {
  return new Promise((resolve, reject) => {
    let step = 0, response = "";
    Bun.connect({
      hostname: "127.0.0.1", port: PP,
      socket: {
        open(s) {
          s.write(Buffer.from(`CONNECT 127.0.0.1:${TP} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n`));
        },
        data(s, data) {
          const b = Buffer.from(data);
          if (step === 0) {
            s.write(Buffer.from("GET /test HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"));
            step = 1;
          } else {
            response += b.toString();
          }
        },
        close() { resolve(response); },
        error(s, e) { reject(e); },
      }, data: {},
    });
    setTimeout(() => resolve(response), 5000);
  });
}

describe("VMess E2E via local server", () => {
  test("SOCKS5 → VMess → target", async () => {
    const result = await socks5Request();
    expect(result).toContain("HTTP/1.1 200 OK");
    expect(result).toContain("Hello VMess!");
  });

  test("HTTP CONNECT → VMess → target", async () => {
    const result = await httpConnectRequest();
    expect(result).toContain("HTTP/1.1 200 OK");
    expect(result).toContain("Hello VMess!");
  });
});
