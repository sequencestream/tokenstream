// Pinned-client compatibility through the real Tokenstream process.
//
// The gateway is started as a real process, providers and gateway credentials
// are created through its administration API, and the pinned clients then talk
// to it over the data plane. This proves the production entry points, routing,
// credential replacement and per-transport logging rather than a mock upstream.
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { startGateway, waitFor } from "./gateway.mjs";
import { startUpstream } from "./upstream.mjs";

const UPSTREAM_KEY = "upstream-only-secret";

function run(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"], ...options });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    const timer = setTimeout(() => child.kill("SIGKILL"), 120000);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      code === 0 ? resolve({ stdout, stderr }) : reject(new Error(`exit ${code}\n${stdout}\n${stderr}`));
    });
  });
}

async function requestLogs(gateway) {
  const response = await fetch(`http://127.0.0.1:${gateway.adminPort}/admin/api/request-logs?limit=100`, {
    headers: { cookie: gateway.auth.cookie, "x-csrf-token": gateway.auth["x-csrf-token"] },
  });
  assert.equal(response.status, 200);
  return (await response.json()).items;
}

const directory = await mkdtemp(join(tmpdir(), "tokenstream-gateway-compat-"));
const upstream = await startUpstream({ upstreamKey: UPSTREAM_KEY });
let gateway;

try {
  gateway = await startGateway({ databasePath: join(directory, "compat.db") });
  const openaiKey = await gateway.createProvider({
    name: "openai",
    protocolType: "openai",
    endpoint: `http://127.0.0.1:${upstream.port}/prefix`,
    upstreamApiKey: UPSTREAM_KEY,
  });
  const anthropicKey = await gateway.createProvider({
    name: "anthropic",
    protocolType: "anthropic",
    endpoint: `http://127.0.0.1:${upstream.port}/prefix`,
    upstreamApiKey: UPSTREAM_KEY,
  });
  const baseURL = `${gateway.baseURL}/v1`;

  console.log("checking OpenAI SDK chat completions through the gateway");
  const openai = new OpenAI({ apiKey: openaiKey, baseURL, maxRetries: 0 });
  const chat = await openai.chat.completions.create({
    model: "compat-model",
    messages: [{ role: "user", content: "compatibility" }],
  });
  assert.equal(chat.choices[0].message.content, "chat-ok");

  console.log("checking OpenAI SDK Responses SSE through the gateway");
  const stream = await openai.responses.create({ model: "compat-model", input: "compatibility", stream: true });
  let responseText = "";
  for await (const event of stream) {
    if (event.type === "response.output_text.delta") responseText += event.delta;
  }
  assert.equal(responseText, "responses-ok");

  console.log("checking Anthropic SDK Messages SSE through the gateway");
  const anthropic = new Anthropic({ apiKey: anthropicKey, baseURL: gateway.baseURL, maxRetries: 0 });
  const messageStream = anthropic.messages.stream({
    model: "compat-model",
    max_tokens: 16,
    messages: [{ role: "user", content: "compatibility" }],
  });
  assert.equal(await messageStream.finalText(), "messages-ok");

  console.log("checking Codex CLI Responses over WebSocket through the gateway");
  upstream.state.refuseWebSocket = false;
  const codexHome = await mkdtemp(join(tmpdir(), "tokenstream-codex-home-"));
  const codexConfig = (extra) => `
model = "compat-model"
model_provider = "tokenstream"
model_reasoning_effort = "low"

[model_providers.tokenstream]
name = "Tokenstream gateway fixture"
base_url = "${baseURL}"
env_key = "OPENAI_API_KEY"
wire_api = "responses"
supports_websockets = true
websocket_connect_timeout_ms = 5000
request_max_retries = 0
stream_max_retries = 0
${extra}
`;
  const codexEnv = {
    PATH: process.env.PATH,
    CODEX_HOME: codexHome,
    OPENAI_API_KEY: openaiKey,
    NO_PROXY: "127.0.0.1,localhost",
    no_proxy: "127.0.0.1,localhost",
    HTTP_PROXY: "",
    HTTPS_PROXY: "",
    ALL_PROXY: "",
  };
  const codexBinary = join(process.cwd(), "node_modules", ".bin", "codex");
  const codexArgs = ["exec", "--skip-git-repo-check", "--sandbox", "read-only", "--color", "never"];
  try {
    await writeFile(join(codexHome, "config.toml"), codexConfig(""));
    const websocketRun = await run(codexBinary, [...codexArgs, "Reply with the compatibility marker and do nothing else."], {
      cwd: codexHome,
      env: codexEnv,
    });
    assert.match(`${websocketRun.stdout}\n${websocketRun.stderr}`, /responses-ok/);
    assert.doesNotMatch(websocketRun.stderr, /Falling back from WebSockets/);
    const websocketMessages = upstream.state.requests.filter((item) => item.method === "MESSAGE");
    assert(websocketMessages.length > 0, "the pinned client never used the WebSocket route");
    assert(
      websocketMessages.some((item) => item.body.includes('"response.create"')),
      "the pinned client never sent response.create over WebSocket",
    );

    console.log("checking the pinned client's own fallback when the upstream refuses the handshake");
    upstream.state.refuseWebSocket = true;
    const fallbackRun = await run(codexBinary, [...codexArgs, "Reply with the compatibility marker and do nothing else."], {
      cwd: codexHome,
      env: codexEnv,
    });
    assert.match(`${fallbackRun.stdout}\n${fallbackRun.stderr}`, /responses-ok/);
    assert.match(
      fallbackRun.stderr,
      /Falling back from WebSockets to HTTPS transport/,
      "the pinned client did not fall back on its own after the refused handshake",
    );
    const refused = upstream.state.requests.filter((item) => item.upgrade);
    const lastUpgrade = refused.at(-1);
    const upgradeCountBefore = upstream.state.requests.filter((item) => item.upgrade).length;
    const fallbackRequest = upstream.state.requests.find(
      (item) => item.path.endsWith("/v1/responses") && !item.upgrade && item.body.includes("Reply with the compatibility marker"),
    );
    assert(
      upgradeCountBefore > websocketMessages.length,
      "the refused handshake never reached the upstream",
    );
    assert(fallbackRequest, "the pinned client never retried over HTTP after the refused handshake");
    assert(lastUpgrade, "no refused WebSocket handshake reached the upstream");
  } finally {
    await rm(codexHome, { recursive: true, force: true });
    upstream.state.refuseWebSocket = false;
  }

  console.log("checking credential replacement and per-transport logging");
  for (const record of upstream.state.requests) {
    if (record.method === "MESSAGE") continue;
    const presented = record.path.endsWith("/v1/messages")
      ? record.xApiKey
      : record.authorization?.replace(/^Bearer /, "");
    assert.notEqual(presented, openaiKey, "the gateway forwarded its own gateway credential");
    assert.notEqual(presented, anthropicKey, "the gateway forwarded its own gateway credential");
    assert.equal(presented, UPSTREAM_KEY, "the upstream did not receive the replaced credential");
    assert.match(record.path, /^\/prefix\/v1\//, "the provider endpoint prefix was not applied");
  }
  assert.equal(
    upstream.state.requests.filter((item) => item.upgrade).length > 0,
    true,
    "no WebSocket transport reached the upstream",
  );

  // The log worker batches asynchronously, so the WebSocket lifecycle rows may
  // still be in flight when the clients have finished.
  await waitFor(async () => {
    const rows = await requestLogs(gateway);
    return rows.some((row) => row.transport_type === "web_socket");
  }, "the WebSocket lifecycle was never logged");
  const logs = await requestLogs(gateway);
  const byTransport = new Set(logs.map((row) => row.transport_type));
  assert(byTransport.has("http"), "no HTTP request log was written through the real process");
  assert(byTransport.has("web_socket"), "no WebSocket request log was written through the real process");
  assert.equal(new Set(logs.map((row) => row.request_id)).size, logs.length, "request identifiers must be unique");
  const serialized = JSON.stringify(logs);
  assert(!serialized.includes(UPSTREAM_KEY), "a request log leaked the upstream credential");
  assert(!serialized.includes(openaiKey), "a request log leaked a gateway credential");
  for (const row of logs) assert(!String(row.path).includes("?"), "a request log recorded the query string");
  console.log(`pinned clients passed through the gateway; ${upstream.state.requests.length} upstream requests, ${logs.length} logs`);
} finally {
  if (gateway) await gateway.stop();
  await upstream.close();
  await rm(directory, { recursive: true, force: true });
}
