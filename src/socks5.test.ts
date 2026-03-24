import { test, expect, describe, beforeAll, afterAll } from "bun:test";
import { createServer, type ProxyConfig } from "./socks5";
import { type TCPSocketListener } from "bun";

const TEST_PORT = 13080;
const TEST_AUTH_PORT = 13081;

let server: TCPSocketListener<unknown>;
let authServer: TCPSocketListener<unknown>;

beforeAll(() => {
  server = createServer({ port: TEST_PORT, host: "127.0.0.1" });
  authServer = createServer({
    port: TEST_AUTH_PORT,
    host: "127.0.0.1",
    auth: { username: "user", password: "pass" },
  });
});

afterAll(() => {
  server.stop(true);
  authServer.stop(true);
});

// ============================================================
// Helpers
// ============================================================

async function rawConnect(port: number): Promise<{
  write: (data: Uint8Array) => void;
  read: () => Promise<Buffer>;
  close: () => void;
}> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let onData: ((chunk: Buffer) => void) | null = null;

    const socket = Bun.connect({
      hostname: "127.0.0.1",
      port,
      socket: {
        open(s) {
          resolve({
            write(data: Uint8Array) {
              s.write(data);
            },
            read() {
              return new Promise<Buffer>((res) => {
                if (chunks.length > 0) {
                  res(chunks.shift()!);
                } else {
                  onData = (chunk) => res(chunk);
                }
              });
            },
            close() {
              s.end();
            },
          });
        },
        data(_s, data) {
          const buf = Buffer.from(data);
          if (onData) {
            const cb = onData;
            onData = null;
            cb(buf);
          } else {
            chunks.push(buf);
          }
        },
        close() {},
        error() {},
      },
      data: {},
    });
  });
}

function socks5Greeting(methods: number[] = [0x00]): Buffer {
  return Buffer.from([0x05, methods.length, ...methods]);
}

function socks5ConnectRequest(host: string, port: number): Buffer {
  const hostBuf = Buffer.from(host);
  return Buffer.from([
    0x05, 0x01, 0x00, 0x03,
    hostBuf.length, ...hostBuf,
    (port >> 8) & 0xff, port & 0xff,
  ]);
}

function socks5AuthPacket(username: string, password: string): Buffer {
  const uBuf = Buffer.from(username);
  const pBuf = Buffer.from(password);
  return Buffer.from([0x01, uBuf.length, ...uBuf, pBuf.length, ...pBuf]);
}

// ============================================================
// SOCKS5 — No Auth
// ============================================================

describe("SOCKS5 no-auth", () => {
  test("greeting accepts no-auth method", async () => {
    const conn = await rawConnect(TEST_PORT);
    conn.write(socks5Greeting([0x00]));
    const reply = await conn.read();
    expect(reply[0]).toBe(0x05); // VER
    expect(reply[1]).toBe(0x00); // NO AUTH
    conn.close();
  });

  test("greeting rejects unsupported method", async () => {
    const conn = await rawConnect(TEST_PORT);
    conn.write(socks5Greeting([0x03])); // only method 0x03 which doesn't exist
    const reply = await conn.read();
    expect(reply[0]).toBe(0x05);
    expect(reply[1]).toBe(0xff); // NO ACCEPTABLE
    conn.close();
  });

  test("connect to httpbin via domain", async () => {
    const conn = await rawConnect(TEST_PORT);
    conn.write(socks5Greeting());
    await conn.read(); // greeting reply

    conn.write(socks5ConnectRequest("httpbin.org", 80));
    const reply = await conn.read();
    expect(reply[0]).toBe(0x05);
    expect(reply[1]).toBe(0x00); // SUCCESS

    // Send a simple HTTP request through the tunnel
    conn.write(Buffer.from("GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"));
    const response = await conn.read();
    expect(response.toString()).toContain("HTTP/1.1 200");
    conn.close();
  });

  test("connect to IPv4 address", async () => {
    const conn = await rawConnect(TEST_PORT);
    conn.write(socks5Greeting());
    await conn.read();

    // Connect to 1.1.1.1:80 (Cloudflare)
    const req = Buffer.from([
      0x05, 0x01, 0x00, 0x01,  // VER CMD RSV ATYP_IPV4
      1, 1, 1, 1,               // 1.1.1.1
      0x00, 0x50,               // port 80
    ]);
    conn.write(req);
    const reply = await conn.read();
    expect(reply[0]).toBe(0x05);
    expect(reply[1]).toBe(0x00);
    conn.close();
  });

  test("rejects unsupported BIND command", async () => {
    const conn = await rawConnect(TEST_PORT);
    conn.write(socks5Greeting());
    await conn.read();

    // CMD = 0x02 (BIND) — not supported
    conn.write(Buffer.from([0x05, 0x02, 0x00, 0x03, 4, ...Buffer.from("test"), 0x00, 0x50]));
    const reply = await conn.read();
    expect(reply[1]).toBe(0x07); // COMMAND NOT SUPPORTED
    conn.close();
  });

  test("rejects invalid version", async () => {
    const conn = await rawConnect(TEST_PORT);
    conn.write(Buffer.from([0x04, 0x01, 0x00])); // SOCKS4
    // Server should close connection — we just verify no crash
    await Bun.sleep(100);
    conn.close();
  });
});

// ============================================================
// SOCKS5 — With Auth
// ============================================================

describe("SOCKS5 with auth", () => {
  test("correct credentials succeed", async () => {
    const conn = await rawConnect(TEST_AUTH_PORT);
    conn.write(socks5Greeting([0x02])); // username/password method
    const greetReply = await conn.read();
    expect(greetReply[1]).toBe(0x02);

    conn.write(socks5AuthPacket("user", "pass"));
    const authReply = await conn.read();
    expect(authReply[1]).toBe(0x00); // auth success
    conn.close();
  });

  test("wrong credentials rejected", async () => {
    const conn = await rawConnect(TEST_AUTH_PORT);
    conn.write(socks5Greeting([0x02]));
    await conn.read();

    conn.write(socks5AuthPacket("user", "wrong"));
    const authReply = await conn.read();
    expect(authReply[1]).toBe(0x01); // auth failure
    conn.close();
  });

  test("no-auth method rejected when auth required", async () => {
    const conn = await rawConnect(TEST_AUTH_PORT);
    conn.write(socks5Greeting([0x00])); // only no-auth
    const reply = await conn.read();
    expect(reply[1]).toBe(0xff); // NO ACCEPTABLE
    conn.close();
  });
});

// ============================================================
// HTTP CONNECT (HTTPS proxy)
// ============================================================

describe("HTTP CONNECT", () => {
  test("tunnel to httpbin via CONNECT", async () => {
    const conn = await rawConnect(TEST_PORT);
    conn.write(Buffer.from("CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org:443\r\n\r\n"));
    const reply = await conn.read();
    const replyStr = reply.toString();
    expect(replyStr).toContain("200 Connection Established");
    conn.close();
  });

  test("CONNECT with auth — correct credentials", async () => {
    const conn = await rawConnect(TEST_AUTH_PORT);
    const creds = Buffer.from("user:pass").toString("base64");
    conn.write(Buffer.from(
      `CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org\r\nProxy-Authorization: Basic ${creds}\r\n\r\n`
    ));
    const reply = await conn.read();
    expect(reply.toString()).toContain("200");
    conn.close();
  });

  test("CONNECT with auth — missing credentials returns 407", async () => {
    const conn = await rawConnect(TEST_AUTH_PORT);
    conn.write(Buffer.from("CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"));
    const reply = await conn.read();
    expect(reply.toString()).toContain("407");
    conn.close();
  });

  test("CONNECT with auth — wrong credentials returns 407", async () => {
    const conn = await rawConnect(TEST_AUTH_PORT);
    const creds = Buffer.from("user:wrong").toString("base64");
    conn.write(Buffer.from(
      `CONNECT httpbin.org:443 HTTP/1.1\r\nProxy-Authorization: Basic ${creds}\r\n\r\n`
    ));
    const reply = await conn.read();
    expect(reply.toString()).toContain("407");
    conn.close();
  });
});

// ============================================================
// HTTP plain proxy
// ============================================================

describe("HTTP plain proxy", () => {
  test("proxy GET request with absolute URL", async () => {
    const conn = await rawConnect(TEST_PORT);
    conn.write(Buffer.from(
      "GET http://httpbin.org/get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"
    ));
    const reply = await conn.read();
    expect(reply.toString()).toContain("HTTP/1.1 200");
    conn.close();
  });

  test("proxy strips Proxy-* headers", async () => {
    const conn = await rawConnect(TEST_PORT);
    conn.write(Buffer.from(
      "GET http://httpbin.org/headers HTTP/1.1\r\nHost: httpbin.org\r\nProxy-Connection: keep-alive\r\nConnection: close\r\n\r\n"
    ));
    const reply = await conn.read();
    const str = reply.toString();
    expect(str).toContain("HTTP/1.1 200");
    // httpbin /headers returns all received headers — Proxy-Connection should be stripped
    expect(str.toLowerCase()).not.toContain("proxy-connection");
    conn.close();
  });

  test("invalid URL returns 400", async () => {
    const conn = await rawConnect(TEST_PORT);
    conn.write(Buffer.from("GET not-a-url HTTP/1.1\r\n\r\n"));
    const reply = await conn.read();
    expect(reply.toString()).toContain("400");
    conn.close();
  });

  test("plain HTTP with auth — missing returns 407", async () => {
    const conn = await rawConnect(TEST_AUTH_PORT);
    conn.write(Buffer.from("GET http://httpbin.org/get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"));
    const reply = await conn.read();
    expect(reply.toString()).toContain("407");
    conn.close();
  });
});

// ============================================================
// Protocol detection edge cases
// ============================================================

describe("protocol detection", () => {
  test("non-SOCKS5, non-HTTP byte closes connection", async () => {
    const conn = await rawConnect(TEST_PORT);
    conn.write(Buffer.from([0x00, 0x01, 0x02])); // garbage
    await Bun.sleep(100);
    conn.close();
  });

  test("empty data does not crash", async () => {
    const conn = await rawConnect(TEST_PORT);
    await Bun.sleep(100);
    conn.close();
  });
});
