import { createServer, type ProxyConfig } from "./src/socks5";
import type { VMessUpstream } from "./src/vmess/vmess";
import { parseArgs } from "node:util";

// --- CLI ---

const { values: args, positionals } = parseArgs({
  args: process.argv.slice(2),
  options: {
    port:  { type: "string", short: "p", default: process.env.SOCKS5_PORT || "3080" },
    host:  { type: "string", short: "h", default: process.env.SOCKS5_HOST || "0.0.0.0" },
    user:  { type: "string", short: "u", default: process.env.SOCKS5_USER },
    pass:  { type: "string", default: process.env.SOCKS5_PASS },
    vmess: { type: "boolean", default: false },
    help:  { type: "boolean", default: false },
  },
  allowPositionals: true,
  strict: true,
});

// --vmess          → read from .env VMESS
// --vmess vmess:// → use the given URI
const vmessArg = args.vmess
  ? (positionals[0]?.startsWith("vmess://") ? positionals[0] : process.env.VMESS || "")
  : "";

if (args.help) {
  console.log(`
Usage: bun run start [options]

Options:
  -p, --port <port>       Listen port (default: 3080)
  -h, --host <host>       Listen address (default: 0.0.0.0)
  -u, --user <user>       Auth username
      --pass <pass>       Auth password
      --vmess             Enable VMess upstream (read URI from .env VMESS)
      --vmess vmess://... Enable VMess with given URI
      --help              Show this help

Examples:
  bun run start                                    # Direct proxy on :3080
  bun run start -p 8080                            # Custom port
  bun run start --vmess                            # VMess from .env
  bun run start --vmess "vmess://eyJ..."           # VMess with URI
  bun run start -u admin --pass secret             # With auth
`);
  process.exit(0);
}

// --- Parse vmess:// URI ---

function parseVMessURI(uri: string): VMessUpstream | undefined {
  if (!uri) return undefined;
  const base64 = uri.replace(/^vmess:\/\//, "");
  try {
    const json = JSON.parse(Buffer.from(base64, "base64").toString());
    const security = json.scy === "auto" || !json.scy ? "aes-128-gcm" : json.scy;
    const network = json.net === "ws" ? "ws" : "tcp";
    const tls = json.tls === "tls";
    return {
      address: json.add,
      port: Number(json.port),
      uuid: json.id,
      security,
      network,
      tls,
      wsPath: json.path || "/",
      wsHost: json.host || json.add,
    };
  } catch {
    console.error("Failed to parse vmess:// URI");
    return undefined;
  }
}

const vmess = parseVMessURI(vmessArg);

const config: ProxyConfig = {
  port: Number(args.port),
  host: args.host!,
  auth:
    args.user && args.pass
      ? { username: args.user, password: args.pass }
      : undefined,
  vmess,
};

const server = createServer(config);

const mode = config.vmess
  ? `VMess → ${config.vmess.address}:${config.vmess.port} (${config.vmess.security}, ${config.vmess.network || "tcp"}${config.vmess.tls ? "+tls" : ""})`
  : "direct";

console.log(
  `Proxy listening on ${config.host}:${config.port} [SOCKS5 + HTTP] [upstream: ${mode}] [auth: ${config.auth ? "yes" : "no"}]`,
);

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\nShutting down...");
  server.stop();
  process.exit(0);
});

process.on("SIGTERM", () => {
  server.stop();
  process.exit(0);
});
