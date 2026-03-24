import { type Socket, type TCPSocketListener } from "bun";
import { type VMessUpstream, createVMessSession, type VMessSession, connectVMess } from "./vmess/vmess";

// --- SOCKS5 Constants (RFC 1928) ---

const SOCKS_VERSION = 0x05;

const AUTH_NO_AUTH = 0x00;
const AUTH_USERNAME_PASSWORD = 0x02;
const AUTH_NO_ACCEPTABLE = 0xff;

const CMD_CONNECT = 0x01;

const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x03;
const ATYP_IPV6 = 0x04;

const REP_SUCCESS = 0x00;
const REP_GENERAL_FAILURE = 0x01;
const REP_HOST_UNREACHABLE = 0x04;
const REP_COMMAND_NOT_SUPPORTED = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;

// --- Types ---

export interface ProxyConfig {
  port: number;
  host: string;
  auth?: { username: string; password: string };
  vmess?: VMessUpstream;
}

const enum Protocol {
  Unknown,
  SOCKS5,
  HTTP,
}

export const STATE_FORWARDING = 4;

const enum State {
  Detect,        // First packet — detect protocol
  // SOCKS5 states
  SocksAuth,
  SocksRequest,
  // HTTP states
  HttpRequest,   // Waiting for full HTTP request header
  // Shared
  Forwarding,    // = 4
}

interface ClientData {
  state: State;
  protocol: Protocol;
  remote: Socket<RemoteData> | null;
  buffer: Buffer | null;
  encoder?: (data: Buffer) => Buffer; // VMess chunk encoder for outbound
}

interface RemoteData {
  client: Socket<ClientData>;
}

// --- Shared remote socket handler ---

function createRemoteHandler(socket: Socket<ClientData>, onConnected?: () => void) {
  return {
    open(remote: Socket<RemoteData>) {
      socket.data.remote = remote;
      socket.data.state = State.Forwarding;
      onConnected?.();

      // Flush any buffered data
      if (socket.data.buffer) {
        remote.write(socket.data.buffer);
        socket.data.buffer = null;
      }
    },

    data(remote: Socket<RemoteData>, data: Buffer) {
      const written = remote.data.client.write(data);
      if (written === 0) {
        remote.pause();
      }
    },

    close(remote: Socket<RemoteData>) {
      remote.data.client.end();
    },

    error(remote: Socket<RemoteData>) {
      remote.end();
    },

    drain(remote: Socket<RemoteData>) {
      remote.data.client.resume();
    },

    connectError(_remote: Socket<RemoteData>, _err: Error) {
      if (socket.data.protocol === Protocol.SOCKS5) {
        sendSocksReply(socket, REP_HOST_UNREACHABLE);
      } else {
        socket.write("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
      }
      socket.end();
    },
  };
}

let vmessSession: VMessSession | null = null;

async function connectToRemote(
  socket: Socket<ClientData>,
  host: string,
  port: number,
  onConnected?: () => void,
) {
  const errorReply = () => {
    if (socket.data.protocol === Protocol.SOCKS5) {
      sendSocksReply(socket, REP_HOST_UNREACHABLE);
    } else {
      socket.write("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
    }
    socket.end();
  };

  if (vmessSession) {
    // Route through VMess upstream
    connectVMess(socket, host, port, vmessSession, onConnected, errorReply);
  } else {
    // Direct connection
    try {
      await Bun.connect<RemoteData>({
        hostname: host,
        port,
        socket: createRemoteHandler(socket, onConnected),
        data: { client: socket },
      });
    } catch {
      errorReply();
    }
  }
}

// --- Server ---

export function createServer(config: ProxyConfig): TCPSocketListener<ClientData> {
  const requireAuth = !!config.auth;

  // Initialize VMess session if upstream configured
  if (config.vmess) {
    vmessSession = createVMessSession(config.vmess);
  } else {
    vmessSession = null;
  }

  return Bun.listen<ClientData>({
    hostname: config.host,
    port: config.port,
    socket: {
      open(socket) {
        socket.data = {
          state: State.Detect,
          protocol: Protocol.Unknown,
          remote: null,
          buffer: null,
        };
      },

      data(socket, data) {
        const raw = Buffer.from(data);

        switch (socket.data.state) {
          case State.Detect:
            detectProtocol(socket, raw, requireAuth, config.auth);
            break;
          case State.SocksAuth:
            handleSocksAuth(socket, raw, config.auth!);
            break;
          case State.SocksRequest:
            handleSocksRequest(socket, raw);
            break;
          case State.HttpRequest:
            handleHttpData(socket, raw);
            break;
          case State.Forwarding:
            if (socket.data.encoder) {
              socket.data.remote?.write(socket.data.encoder(raw));
            } else {
              socket.data.remote?.write(raw);
            }
            break;
        }
      },

      close(socket) {
        socket.data.remote?.end();
        socket.data.remote = null;
        socket.data.buffer = null;
      },

      error(socket) {
        socket.end();
      },

      drain(socket) {
        socket.data.remote?.resume();
      },
    },
  });
}

// --- Protocol Detection ---

function detectProtocol(
  socket: Socket<ClientData>,
  data: Buffer,
  requireAuth: boolean,
  auth?: { username: string; password: string },
) {
  if (data.length === 0) return;

  const firstByte = data[0]!;

  if (firstByte === SOCKS_VERSION) {
    // SOCKS5
    socket.data.protocol = Protocol.SOCKS5;
    handleSocksGreeting(socket, data, requireAuth);
  } else if (firstByte >= 0x41 && firstByte <= 0x5a) {
    // ASCII uppercase letter — likely HTTP method (GET, POST, CONNECT, etc.)
    socket.data.protocol = Protocol.HTTP;

    if (requireAuth && !checkHttpAuth(socket, data, auth!)) {
      return;
    }

    socket.data.state = State.HttpRequest;
    handleHttpData(socket, data);
  } else {
    socket.end();
  }
}

// ============================================================
// SOCKS5 Handlers
// ============================================================

function handleSocksGreeting(socket: Socket<ClientData>, data: Buffer, requireAuth: boolean) {
  if (data.length < 3 || data[0] !== SOCKS_VERSION) {
    socket.end();
    return;
  }

  const nmethods = data[1];
  const methods = data.slice(2, 2 + nmethods);

  if (requireAuth) {
    if (methods.includes(AUTH_USERNAME_PASSWORD)) {
      socket.write(Buffer.from([SOCKS_VERSION, AUTH_USERNAME_PASSWORD]));
      socket.data.state = State.SocksAuth;
    } else {
      socket.write(Buffer.from([SOCKS_VERSION, AUTH_NO_ACCEPTABLE]));
      socket.end();
    }
  } else {
    if (methods.includes(AUTH_NO_AUTH)) {
      socket.write(Buffer.from([SOCKS_VERSION, AUTH_NO_AUTH]));
      socket.data.state = State.SocksRequest;
    } else {
      socket.write(Buffer.from([SOCKS_VERSION, AUTH_NO_ACCEPTABLE]));
      socket.end();
    }
  }
}

function handleSocksAuth(
  socket: Socket<ClientData>,
  data: Buffer,
  auth: { username: string; password: string },
) {
  if (data.length < 5 || data[0] !== 0x01) {
    socket.write(Buffer.from([0x01, 0x01]));
    socket.end();
    return;
  }

  const ulen = data[1];
  const username = data.slice(2, 2 + ulen).toString();
  const plen = data[2 + ulen];
  const password = data.slice(3 + ulen, 3 + ulen + plen).toString();

  if (username === auth.username && password === auth.password) {
    socket.write(Buffer.from([0x01, 0x00]));
    socket.data.state = State.SocksRequest;
  } else {
    socket.write(Buffer.from([0x01, 0x01]));
    socket.end();
  }
}

function handleSocksRequest(socket: Socket<ClientData>, data: Buffer) {
  if (data.length < 7 || data[0] !== SOCKS_VERSION) {
    sendSocksReply(socket, REP_GENERAL_FAILURE);
    socket.end();
    return;
  }

  const cmd = data[1];
  if (cmd !== CMD_CONNECT) {
    sendSocksReply(socket, REP_COMMAND_NOT_SUPPORTED);
    socket.end();
    return;
  }

  const atyp = data[3];
  let host: string;
  let portOffset: number;

  switch (atyp) {
    case ATYP_IPV4:
      if (data.length < 10) { sendSocksReply(socket, REP_GENERAL_FAILURE); socket.end(); return; }
      host = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
      portOffset = 8;
      break;

    case ATYP_DOMAIN: {
      const domainLen = data[4];
      if (data.length < 5 + domainLen + 2) { sendSocksReply(socket, REP_GENERAL_FAILURE); socket.end(); return; }
      host = data.slice(5, 5 + domainLen).toString();
      portOffset = 5 + domainLen;
      break;
    }

    case ATYP_IPV6:
      if (data.length < 22) { sendSocksReply(socket, REP_GENERAL_FAILURE); socket.end(); return; }
      const parts: string[] = [];
      for (let i = 0; i < 16; i += 2) {
        parts.push(((data[4 + i] << 8) | data[4 + i + 1]).toString(16));
      }
      host = parts.join(":");
      portOffset = 20;
      break;

    default:
      sendSocksReply(socket, REP_ADDRESS_TYPE_NOT_SUPPORTED);
      socket.end();
      return;
  }

  const port = (data[portOffset] << 8) | data[portOffset + 1];

  connectToRemote(socket, host, port, () => {
    sendSocksReply(socket, REP_SUCCESS);
  });
}

function sendSocksReply(socket: Socket<ClientData>, rep: number) {
  socket.write(
    Buffer.from([
      SOCKS_VERSION, rep, 0x00, ATYP_IPV4,
      0, 0, 0, 0,  // BND.ADDR
      0, 0,         // BND.PORT
    ]),
  );
}

// ============================================================
// HTTP/HTTPS Proxy Handlers
// ============================================================

function checkHttpAuth(
  socket: Socket<ClientData>,
  data: Buffer,
  auth: { username: string; password: string },
): boolean {
  const header = data.toString();
  const authMatch = header.match(/Proxy-Authorization:\s*Basic\s+(\S+)/i) as RegExpMatchArray | null;

  if (!authMatch) {
    socket.write(
      "HTTP/1.1 407 Proxy Authentication Required\r\n" +
      "Proxy-Authenticate: Basic realm=\"proxy\"\r\n" +
      "Connection: close\r\n\r\n",
    );
    socket.end();
    return false;
  }

  const decoded = Buffer.from(authMatch[1]!, "base64").toString();
  const [username, ...rest] = decoded.split(":");
  const password = rest.join(":");

  if (username !== auth.username || password !== auth.password) {
    socket.write("HTTP/1.1 407 Proxy Authentication Required\r\nConnection: close\r\n\r\n");
    socket.end();
    return false;
  }

  return true;
}

function handleHttpData(socket: Socket<ClientData>, data: Buffer) {
  // Accumulate data until we have full headers
  if (socket.data.buffer) {
    socket.data.buffer = Buffer.concat([socket.data.buffer, data]);
  } else {
    socket.data.buffer = data;
  }

  const headerStr = socket.data.buffer.toString();
  const headerEnd = headerStr.indexOf("\r\n\r\n");
  if (headerEnd === -1) return; // Headers not complete yet

  const firstLine = headerStr.slice(0, headerStr.indexOf("\r\n"));
  const parts = firstLine.split(" ");
  const method = parts[0]!;
  const target = parts[1]!;

  if (method === "CONNECT") {
    // HTTPS tunnel: CONNECT host:port HTTP/1.1
    handleConnect(socket, target);
  } else {
    // Plain HTTP proxy: GET http://host/path HTTP/1.1
    handlePlainHttp(socket, headerStr, headerEnd);
  }
}

function handleConnect(socket: Socket<ClientData>, target: string) {
  const colonIdx = target.lastIndexOf(":");
  const host = colonIdx > 0 ? target.slice(0, colonIdx) : target;
  const portStr = colonIdx > 0 ? target.slice(colonIdx + 1) : "";
  const port = parseInt(portStr) || 443;

  socket.data.buffer = null;

  connectToRemote(socket, host, port, () => {
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
  });
}

function handlePlainHttp(socket: Socket<ClientData>, headerStr: string, headerEnd: number) {
  const firstLineEnd = headerStr.indexOf("\r\n");
  const firstLine = headerStr.slice(0, firstLineEnd);
  const reqParts = firstLine.split(" ");
  const method = reqParts[0]!;
  const url = reqParts[1]!;
  const httpVersion = reqParts[2]!;

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    socket.write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    socket.end();
    return;
  }

  const host = parsedUrl.hostname;
  const port = parseInt(parsedUrl.port) || 80;
  const path = parsedUrl.pathname + parsedUrl.search;

  // Rewrite the request: absolute URL → relative path, remove proxy headers
  const restHeaders = headerStr.slice(firstLineEnd, headerEnd + 4);
  const cleanedHeaders = restHeaders
    .split("\r\n")
    .filter((line) => !line.match(/^Proxy-/i))
    .join("\r\n");

  const rewritten = `${method} ${path} ${httpVersion}${cleanedHeaders}`;
  const fullBuf = socket.data.buffer!;
  const bodyStart = headerEnd + 4;
  const body = fullBuf.length > bodyStart ? fullBuf.slice(bodyStart) : null;

  // Buffer the rewritten request to send after connection
  socket.data.buffer = body
    ? Buffer.concat([Buffer.from(rewritten), body])
    : Buffer.from(rewritten);

  connectToRemote(socket, host, port);
}
