import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";

const expectedKeys = new Map([
  ["/v1/chat/completions", "openai-gateway-key"],
  ["/v1/responses", "openai-gateway-key"],
  ["/v1/messages", "anthropic-gateway-key"],
]);
const observed = [];

function json(response, status, value) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
  });
  response.end(body);
}

function sse(response, events) {
  response.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "close",
  });
  for (const [event, data] of events) {
    response.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  }
  response.end();
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks);
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url, "http://compatibility.invalid");
  const path = url.pathname;
  const upgrade = request.headers.upgrade?.toLowerCase() === "websocket";
  const expectedKey = expectedKeys.get(path);
  const actualKey = path === "/v1/messages"
    ? request.headers["x-api-key"]
    : request.headers.authorization?.replace(/^Bearer /, "");
  const body = await readBody(request);
  observed.push({ path, method: request.method, upgrade, body: body.toString() });
  response.on("finish", () => console.log(`mock ${request.method} ${path} -> ${response.statusCode}`));

  if (!expectedKey || actualKey !== expectedKey) {
    return json(response, 401, { error: { message: "invalid test credential" } });
  }
  if (path === "/v1/chat/completions") {
    return json(response, 200, {
      id: "chatcmpl_compat",
      object: "chat.completion",
      created: 1,
      model: "compat-model",
      choices: [{ index: 0, message: { role: "assistant", content: "chat-ok" }, finish_reason: "stop" }],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    });
  }
  if (path === "/v1/responses") {
    if (upgrade) return json(response, 503, { error: { message: "websocket unavailable" } });
    const id = `resp_${observed.length}`;
    const created = {
      id,
      object: "response",
      created_at: 1,
      status: "in_progress",
      model: "compat-model",
      output: [],
    };
    const completed = {
      ...created,
      status: "completed",
      output: [{
        id: `msg_${observed.length}`,
        type: "message",
        status: "completed",
        role: "assistant",
        content: [{ type: "output_text", text: "responses-ok", annotations: [] }],
      }],
      usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 },
    };
    const item = {
      id: completed.output[0].id,
      type: "message",
      status: "in_progress",
      role: "assistant",
      content: [],
    };
    const part = { type: "output_text", text: "", annotations: [] };
    return sse(response, [
      ["response.created", { type: "response.created", sequence_number: 0, response: created }],
      ["response.output_item.added", { type: "response.output_item.added", sequence_number: 1, output_index: 0, item }],
      ["response.content_part.added", { type: "response.content_part.added", sequence_number: 2, item_id: item.id, output_index: 0, content_index: 0, part }],
      ["response.output_text.delta", { type: "response.output_text.delta", sequence_number: 3, item_id: item.id, output_index: 0, content_index: 0, delta: "responses-ok" }],
      ["response.output_text.done", { type: "response.output_text.done", sequence_number: 4, item_id: item.id, output_index: 0, content_index: 0, text: "responses-ok" }],
      ["response.content_part.done", { type: "response.content_part.done", sequence_number: 5, item_id: item.id, output_index: 0, content_index: 0, part: completed.output[0].content[0] }],
      ["response.output_item.done", { type: "response.output_item.done", sequence_number: 6, output_index: 0, item: completed.output[0] }],
      ["response.completed", { type: "response.completed", sequence_number: 7, response: completed }],
    ]);
  }
  if (path === "/v1/messages") {
    return sse(response, [
      ["message_start", { type: "message_start", message: { id: "msg_compat", type: "message", role: "assistant", model: "compat-model", content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 0 } } }],
      ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }],
      ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "messages-ok" } }],
      ["content_block_stop", { type: "content_block_stop", index: 0 }],
      ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } }],
      ["message_stop", { type: "message_stop" }],
    ]);
  }
  json(response, 404, { error: { message: "unsupported route" } });
});

server.on("upgrade", (request, socket) => {
  const url = new URL(request.url, "http://compatibility.invalid");
  observed.push({ path: url.pathname, method: request.method, upgrade: true, body: "" });
  console.log(`mock ${request.method} ${url.pathname} websocket -> 503`);
  socket.end("HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\ncontent-length: 45\r\nconnection: close\r\n\r\n{\"error\":{\"message\":\"websocket unavailable\"}}");
});

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", code => code === 0
      ? resolve({ stdout, stderr })
      : reject(new Error(`${command} exited ${code}\n${stdout}\n${stderr}`)));
  });
}

const address = await new Promise(resolve => server.listen(0, "127.0.0.1", () => resolve(server.address())));
const origin = `http://127.0.0.1:${address.port}`;
const baseURL = `${origin}/v1`;

try {
  console.log("checking OpenAI SDK chat completions");
  const openai = new OpenAI({ apiKey: "openai-gateway-key", baseURL });
  const chat = await openai.chat.completions.create({
    model: "compat-model",
    messages: [{ role: "user", content: "compatibility" }],
  });
  assert.equal(chat.choices[0].message.content, "chat-ok");

  console.log("checking OpenAI SDK Responses SSE");
  const responseStream = await openai.responses.create({
    model: "compat-model",
    input: "compatibility",
    stream: true,
  });
  let responseText = "";
  for await (const event of responseStream) {
    if (event.type === "response.output_text.delta") responseText += event.delta;
  }
  assert.equal(responseText, "responses-ok");

  console.log("checking Anthropic SDK Messages SSE");
  const anthropic = new Anthropic({ apiKey: "anthropic-gateway-key", baseURL: origin });
  const messageStream = anthropic.messages.stream({
    model: "compat-model",
    max_tokens: 16,
    messages: [{ role: "user", content: "compatibility" }],
  });
  assert.equal(await messageStream.finalText(), "messages-ok");

  console.log("checking client-owned WebSocket to HTTP fallback");
  await new Promise((resolve, reject) => {
    const socket = connect(address.port, "127.0.0.1", () => socket.write(
      "GET /v1/responses HTTP/1.1\r\n" +
      `host: 127.0.0.1:${address.port}\r\n` +
      "authorization: Bearer openai-gateway-key\r\n" +
      "connection: Upgrade\r\nupgrade: websocket\r\n" +
      "sec-websocket-version: 13\r\nsec-websocket-key: Y29tcGF0aWJpbGl0eQ==\r\n\r\n",
    ));
    let reply = "";
    socket.on("data", chunk => { reply += chunk; });
    socket.on("error", reject);
    socket.on("end", () => {
      assert.match(reply, /^HTTP\/1\.1 503/);
      resolve();
    });
  });
  const fallback = await openai.responses.create({
    model: "compat-model",
    input: "client-owned fallback",
    stream: true,
  });
  for await (const _event of fallback) { /* drain the independent HTTP request */ }

  console.log("checking Codex CLI Responses compatibility");
  const codexHome = await mkdtemp(join(tmpdir(), "tokenstream-codex-"));
  try {
    await writeFile(join(codexHome, "config.toml"), `
model = "compat-model"
model_provider = "tokenstream"
model_reasoning_effort = "low"

[model_providers.tokenstream]
name = "Tokenstream compatibility fixture"
base_url = "${baseURL}"
env_key = "OPENAI_API_KEY"
wire_api = "responses"
request_max_retries = 0
stream_max_retries = 0
`);
    const codex = await run(join(process.cwd(), "node_modules", ".bin", "codex"), [
      "exec",
      "--skip-git-repo-check",
      "--sandbox", "read-only",
      "--color", "never",
      "Reply with the compatibility marker and do nothing else.",
    ], {
      cwd: codexHome,
      env: {
        PATH: process.env.PATH,
        CODEX_HOME: codexHome,
        OPENAI_API_KEY: "openai-gateway-key",
        NO_PROXY: "127.0.0.1,localhost",
        no_proxy: "127.0.0.1,localhost",
        HTTP_PROXY: "",
        HTTPS_PROXY: "",
        ALL_PROXY: "",
      },
    });
    assert.match(`${codex.stdout}\n${codex.stderr}`, /responses-ok/);
  } finally {
    await rm(codexHome, { recursive: true, force: true });
  }

  for (const path of ["/v1/chat/completions", "/v1/responses", "/v1/messages"]) {
    assert(observed.some(request => request.path === path), `missing ${path}`);
  }
  const websocketIndex = observed.findIndex(request => request.upgrade);
  const fallbackIndex = observed.findIndex((request, index) => index > websocketIndex && request.path === "/v1/responses" && !request.upgrade);
  assert(websocketIndex >= 0 && fallbackIndex > websocketIndex, "the fallback must be a new client HTTP request");
  console.log(`compatibility clients passed; ${observed.length} requests observed`);
} finally {
  await new Promise(resolve => server.close(resolve));
}
