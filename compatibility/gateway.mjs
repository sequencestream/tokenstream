// Boots a real Tokenstream process and configures providers through its
// administration API so pinned clients can be exercised through the
// production entry points instead of a mock upstream.
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

// Argon2id hash of the fixture administration password. The gateway only ever
// receives the hash; the password itself is supplied by the profile.
const ADMIN_PASSWORD_HASH = "$argon2id$v=19$m=19456,t=2,p=1$dG9rZW5zdHJlYW0tY29tcGF0LWZpeHR1cmU$z2UAgatnkBTXOJpU20ce7O3HDCj4F840rOFfnn9vQSw";
export const ADMIN_PASSWORD = "compat-admin";

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function request(port, method, path, body, headers = {}) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers,
    body,
    redirect: "manual",
  });
  return {
    status: response.status,
    headers: response.headers,
    text: await response.text(),
  };
}

async function waitFor(check, description, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      if (await check()) return;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`${description}${lastError ? `: ${lastError.message}` : ""}`);
}

export async function startGateway({ databasePath, environment = {} }) {
  const dataPort = await freePort();
  const adminPort = await freePort();
  const values = {
    DATA_LISTEN_ADDR: `127.0.0.1:${dataPort}`,
    ADMIN_LISTEN_ADDR: `127.0.0.1:${adminPort}`,
    DATABASE_URL: `sqlite://${databasePath}`,
    MASTER_KEY: "11".repeat(32),
    ADMIN_PASSWORD_HASH,
    DEVELOPMENT_MODE: "true",
    UPSTREAM_CONNECT_TIMEOUT_MS: "2000",
    UPSTREAM_HEADER_TIMEOUT_MS: "5000",
    STREAM_IDLE_TIMEOUT_MS: "30000",
    SHUTDOWN_DRAIN_TIMEOUT_MS: "500",
    LOG_FLUSH_TIMEOUT_MS: "2000",
    DATABASE_MAX_CONNECTIONS: "8",
    MAX_PROXY_CONNECTIONS: "512",
    LOG_QUEUE_CAPACITY: "4096",
    LOG_BATCH_SIZE: "64",
    LOG_BATCH_INTERVAL_MS: "20",
    PASSWORD_MAX_CONCURRENCY: "4",
    DATA_MAX_CONNECTIONS: "528",
    ADMIN_MAX_CONNECTIONS: "128",
    DOWNSTREAM_HEADER_TIMEOUT_MS: "10000",
    ADMIN_BODY_TIMEOUT_MS: "30000",
    HTTP_BUFFER_BYTES: "65536",
    WEBSOCKET_MAX_FRAME_BYTES: "1048576",
    WEBSOCKET_MAX_MESSAGE_BYTES: "8388608",
    WEBSOCKET_QUEUE_CAPACITY: "32",
    ...environment,
  };
  const child = spawn(join(here, "..", "target", "debug", "tokenstream"), {
    env: {
      ...process.env,
      ...Object.fromEntries(
        Object.entries(values).map(([key, value]) => [`TOKENSTREAM_${key}`, String(value)]),
      ),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  const gateway = {
    dataPort,
    adminPort,
    child,
    baseURL: `http://127.0.0.1:${dataPort}`,
    stderr: () => stderr,
  };

  await waitFor(async () => {
    if (child.exitCode !== null) throw new Error(`gateway exited: ${stderr}`);
    const health = await request(adminPort, "GET", "/healthz");
    return health.status === 200;
  }, "gateway did not listen");

  const session = await request(adminPort, "POST", "/admin/api/session", JSON.stringify({ password: ADMIN_PASSWORD }), {
    "content-type": "application/json",
  });
  if (session.status !== 200) throw new Error(`administration sign-in failed: ${session.text}`);
  const auth = {
    cookie: session.headers.get("set-cookie").split(";")[0],
    "x-csrf-token": JSON.parse(session.text).csrf_token,
    "content-type": "application/json",
  };

  gateway.createProvider = async ({ name, protocolType, endpoint, upstreamApiKey }) => {
    const created = await request(
      adminPort,
      "POST",
      "/admin/api/providers",
      JSON.stringify({
        name,
        protocol_type: protocolType,
        endpoint,
        upstream_api_key: upstreamApiKey,
        status: "enabled",
      }),
      auth,
    );
    if (created.status !== 201) throw new Error(`provider creation failed: ${created.text}`);
    return JSON.parse(created.text).gateway_api_key;
  };
  gateway.auth = auth;

  gateway.stop = async () => {
    if (child.exitCode === null) {
      child.kill("SIGINT");
      await new Promise((resolve) => child.once("exit", resolve));
    }
  };
  return gateway;
}

export function websocketAccept(key) {
  return createHash("sha1").update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
}

export function maskedTextFrame(text) {
  const payload = Buffer.from(text);
  const mask = randomBytes(4);
  const masked = Buffer.from(payload.map((value, index) => value ^ mask[index % 4]));
  return Buffer.concat([Buffer.from([0x81, 0x80 | payload.length]), mask, masked]);
}

export function textFrame(text) {
  const payload = Buffer.from(text);
  if (payload.length < 126) {
    return Buffer.concat([Buffer.from([0x81, payload.length]), payload]);
  }
  const length = Buffer.alloc(2);
  length.writeUInt16BE(payload.length);
  return Buffer.concat([Buffer.from([0x81, 126]), length, payload]);
}

export { waitFor };
