// Controllable upstream used by the production gateway profile. It answers the
// OpenAI and Anthropic routes, can refuse a WebSocket handshake on demand so
// the pinned client's own fallback runs, and records what the gateway sent so
// credential replacement can be verified.
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { connect } from "node:net";

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
  });
  for (const [event, data] of events) {
    response.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  }
  response.end();
}

function responsesEvents(marker, sequence) {
  const response = { id: `resp_${sequence}`, object: "response", created_at: 1, status: "in_progress", model: "compat-model", output: [] };
  const item = { id: `msg_${sequence}`, type: "message", status: "in_progress", role: "assistant", content: [] };
  const part = { type: "output_text", text: "", annotations: [] };
  let step = 0;
  return [
    ["response.created", { type: "response.created", sequence_number: step++, response }],
    ["response.output_item.added", { type: "response.output_item.added", sequence_number: step++, output_index: 0, item }],
    ["response.content_part.added", { type: "response.content_part.added", sequence_number: step++, item_id: item.id, output_index: 0, content_index: 0, part }],
    ["response.output_text.delta", { type: "response.output_text.delta", sequence_number: step++, item_id: item.id, output_index: 0, content_index: 0, delta: marker }],
    ["response.output_text.done", { type: "response.output_text.done", sequence_number: step++, item_id: item.id, output_index: 0, content_index: 0, text: marker }],
    ["response.content_part.done", { type: "response.content_part.done", sequence_number: step++, item_id: item.id, output_index: 0, content_index: 0, part: { ...part, text: marker } }],
    ["response.output_item.done", { type: "response.output_item.done", sequence_number: step++, output_index: 0, item: { ...item, status: "completed", content: [{ type: "output_text", text: marker, annotations: [] }] } }],
    ["response.completed", { type: "response.completed", sequence_number: step, response: { ...response, status: "completed", output: [{ ...item, status: "completed", content: [{ type: "output_text", text: marker, annotations: [] }] }] } }],
  ];
}

export async function startUpstream({ upstreamKey } = {}) {
  const state = { refuseWebSocket: false, requests: observed };
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const url = new URL(request.url, "http://compatibility.invalid");
    const record = {
      path: url.pathname,
      method: request.method,
      upgrade: request.headers.upgrade?.toLowerCase() === "websocket",
      authorization: request.headers.authorization ?? null,
      xApiKey: request.headers["x-api-key"] ?? null,
      requestId: request.headers["x-request-id"] ?? null,
      body: Buffer.concat(chunks).toString(),
    };
    observed.push(record);
    const expected = upstreamKey ?? "openai-gateway-key";
    const presented = url.pathname.endsWith("/v1/messages")
      ? record.xApiKey
      : record.authorization?.replace(/^Bearer /, "");
    if (presented !== expected) return json(response, 401, { error: { message: "invalid upstream credential" } });

    const route = url.pathname.replace(/^\/prefix/, "");
    if (route === "/v1/chat/completions") {
      return json(response, 200, {
        id: "chatcmpl_compat",
        object: "chat.completion",
        created: 1,
        model: "compat-model",
        choices: [{ index: 0, message: { role: "assistant", content: "chat-ok" }, finish_reason: "stop" }],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      });
    }
    if (route === "/v1/responses") {
      return sse(response, responsesEvents("responses-ok", observed.length));
    }
    if (route === "/v1/messages") {
      return sse(response, [
        ["message_start", { type: "message_start", message: { id: "msg_compat", type: "message", role: "assistant", model: "compat-model", content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 0 } } }],
        ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }],
        ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "messages-ok" } }],
        ["content_block_stop", { type: "content_block_stop", index: 0 }],
        ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 4 } }],
        ["message_stop", { type: "message_stop" }],
      ]);
    }
    json(response, 404, { error: { message: "unknown route" } });
  });

  server.on("upgrade", (request, socket) => {
    const url = new URL(request.url, "http://compatibility.invalid");
    observed.push({
      path: url.pathname,
      method: request.method,
      upgrade: true,
      authorization: request.headers.authorization ?? null,
      xApiKey: request.headers["x-api-key"] ?? null,
      requestId: request.headers["x-request-id"] ?? null,
      body: "",
    });
    if (state.refuseWebSocket) {
      socket.end("HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\ncontent-length: 40\r\nconnection: close\r\n\r\n{\"error\":{\"message\":\"websocket unavailable\"}}\r\n");
      return;
    }
    const expected = upstreamKey ?? "openai-gateway-key";
    const presented = url.pathname.endsWith("/v1/messages")
      ? request.headers["x-api-key"]
      : request.headers.authorization?.replace(/^Bearer /, "");
    if (presented !== expected) {
      socket.end("HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: 41\r\nconnection: close\r\n\r\n{\"error\":{\"message\":\"invalid gateway key\"}}\r\n");
      return;
    }
    const accept = createHash("sha1")
      .update(`${request.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest("base64");
    socket.write(
      `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    let buffer = Buffer.alloc(0);
    socket.on("error", () => socket.destroy());
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 2) {
        const opcode = buffer[0] & 15;
        const masked = (buffer[1] & 128) !== 0;
        const short = buffer[1] & 127;
        let offset = 2;
        let length = short;
        if (short === 126) {
          if (buffer.length < 4) return;
          length = buffer.readUInt16BE(2);
          offset = 4;
        } else if (short === 127) {
          if (buffer.length < 10) return;
          length = Number(buffer.readBigUInt64BE(2));
          offset = 10;
        }
        let mask = null;
        if (masked) {
          if (buffer.length < offset + 4) return;
          mask = buffer.subarray(offset, offset + 4);
          offset += 4;
        }
        if (buffer.length < offset + length) return;
        const raw = buffer.subarray(offset, offset + length);
        buffer = buffer.subarray(offset + length);
        const payload = mask ? Buffer.from(raw.map((value, index) => value ^ mask[index % 4])) : raw;
        if (opcode === 8) {
          socket.end(Buffer.from([0x88, 0x02, 0x03, 0xe8]));
          return;
        }
        if (opcode !== 1 && opcode !== 2) continue;
        let event;
        try {
          event = JSON.parse(payload.toString());
        } catch {
          socket.destroy();
          return;
        }
        observed.push({
          path: url.pathname,
          method: "MESSAGE",
          upgrade: true,
          authorization: request.headers.authorization ?? null,
          xApiKey: request.headers["x-api-key"] ?? null,
          requestId: request.headers["x-request-id"] ?? null,
          body: payload.toString().slice(0, 200),
        });
        if (event.type !== "response.create") continue;
        const marker = typeof event.input === "string" ? event.input : "responses-ok";
        for (const text of responsesEvents(marker, observed.length)) {
          const body = Buffer.from(JSON.stringify(text[1]));
          const header =
            body.length < 126
              ? Buffer.from([0x81, body.length])
              : Buffer.concat([Buffer.from([0x81, 126]), (() => { const two = Buffer.alloc(2); two.writeUInt16BE(body.length); return two; })()]);
          socket.write(Buffer.concat([header, body]));
        }
      }
    });
  });

  const sockets = new Set();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  server.on("secureConnection", () => {});
  server.closeAllConnections = () => { for (const socket of sockets) socket.destroy(); };
  server.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  return {
    port: server.address().port,
    state,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(resolve);
      }),
  };
}
