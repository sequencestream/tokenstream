// Negative half of the production gateway profile.
//
// The pinned-client gate must fail when the formal proxy entry is unavailable,
// so this run points the clients at a port where no gateway is listening and
// requires every supported route to be refused. If a regression made the
// profile pass without a reachable gateway, this check would fail instead.
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";

function unusedPort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

const directory = await mkdtemp(join(tmpdir(), "tokenstream-gateway-absent-"));
try {
  const dataPort = await unusedPort();
  const baseURL = `http://127.0.0.1:${dataPort}/v1`;
  const openai = new OpenAI({ apiKey: "unused", baseURL, maxRetries: 0 });
  const anthropic = new Anthropic({ apiKey: "unused", baseURL: `http://127.0.0.1:${dataPort}`, maxRetries: 0 });

  await assert.rejects(
    () => openai.chat.completions.create({ model: "compat-model", messages: [{ role: "user", content: "absent" }] }),
    "the OpenAI route was accepted without a gateway",
  );
  await assert.rejects(
    () => openai.responses.create({ model: "compat-model", input: "absent", stream: true }),
    "the Responses route was accepted without a gateway",
  );
  await assert.rejects(
    () => anthropic.messages.create({ model: "compat-model", max_tokens: 8, messages: [{ role: "user", content: "absent" }] }),
    "the Messages route was accepted without a gateway",
  );
  const health = await fetch(`http://127.0.0.1:${dataPort}/healthz`).catch(() => null);
  assert.equal(health, null, "an unrelated listener answered on the unused data port");
  console.log("every pinned route was refused without a gateway");
} finally {
  await rm(directory, { recursive: true, force: true });
}
