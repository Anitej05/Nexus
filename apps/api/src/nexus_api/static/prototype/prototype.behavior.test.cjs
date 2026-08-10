"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(scriptMatch, "dashboard inline script exists");

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

class FakeElement {
  constructor(id) {
    this.id = id;
    this.textContent = "";
    this.className = "";
    this.dataset = {};
    this.hidden = false;
    this.disabled = false;
    this.href = "";
    this.value = "";
    this.attributes = new Map();
    this.listeners = new Map();
  }

  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  addEventListener(type, listener) { this.listeners.set(type, listener); }
  click() { return this.listeners.get("click")?.({ currentTarget: this }); }
}

const response = (body, ok = true) => ({ ok, json: async () => body });
const runView = ({ hash = HASH_A, status = "awaiting_approval", llmStatus = "available" } = {}) => ({
  run_id: "018f0000-0000-7000-8000-000000000901",
  tenant_name: "Authenticated tenant",
  status,
  seed_digest: "ab6630b92c813392964fad431fe7aba5e2b68f0742e800523d6ceec3196f0e06",
  plan: { plan_hash: hash, status: "awaiting_approval" },
  llm: {
    provider_status: llmStatus,
    model_id: "provider/model-must-not-render",
    prompt_version: "prototype-briefing.v1",
    summary_sha256: "4f6de91b".repeat(8),
    citation_node_ids: ["PORT-MAA"],
  },
});

const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

const settle = async () => {
  for (let index = 0; index < 6; index += 1) await Promise.resolve();
};

const loadDashboard = async (queuedResponses, search = "?run=018f0000-0000-7000-8000-000000000901") => {
  const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
  const elements = Object.fromEntries(ids.map((id) => [id, new FakeElement(id)]));
  const preview = html.match(/<script id="prototype-preview" type="application\/json">([\s\S]*?)<\/script>/);
  assert.ok(preview);
  elements["prototype-preview"].textContent = preview[1];
  const calls = [];
  const queue = [...queuedResponses];
  const fetch = (url, options = {}) => {
    calls.push({ url, options });
    const next = queue.shift();
    if (next === undefined) throw new Error(`Unexpected fetch: ${url}`);
    return Promise.resolve(next);
  };
  const document = {
    body: new FakeElement("body"),
    documentElement: { scrollWidth: 1440, clientWidth: 1440 },
    getElementById: (id) => elements[id] ?? null,
  };
  vm.runInNewContext(scriptMatch[1], {
    document,
    fetch,
    URLSearchParams,
    window: { location: { search }, innerWidth: 1440 },
  });
  await settle();
  return { calls, elements };
};

const connect = async (harness, token = "test-only-ephemeral-token") => {
  harness.elements["bearer-token"].value = token;
  await harness.elements["connect-button"].click();
  await settle();
  assert.equal(harness.elements["bearer-token"].value, "");
};

test("governed mutations quote the exact current plan hash and consume returned state", async () => {
  const harness = await loadDashboard([
    response(runView()),
    response(runView({ hash: HASH_B, status: "approved" })),
    response(runView({ hash: HASH_B, status: "verified" })),
  ]);
  assert.equal(harness.calls.length, 0);
  await connect(harness);
  assert.equal(harness.calls[0].options.headers.Authorization, "Bearer test-only-ephemeral-token");

  await harness.elements["approve-button"].click();
  await settle();
  assert.equal(harness.calls[1].options.headers["If-Match"], `"${HASH_A}"`);
  assert.equal(harness.calls[1].options.headers.Authorization, "Bearer test-only-ephemeral-token");
  assert.equal(harness.elements["top-state"].textContent, "Approved");

  await harness.elements["approve-button"].click();
  await settle();
  assert.equal(harness.calls.filter((call) => call.options.method === "POST").length, 1);

  await harness.elements["execute-button"].click();
  await settle();
  assert.equal(harness.calls[2].options.headers["If-Match"], `"${HASH_B}"`);
  assert.equal(harness.calls[2].options.headers.Authorization, "Bearer test-only-ephemeral-token");
  assert.equal(harness.elements["top-state"].textContent, "Verified");
});

test("governed mutations ignore duplicate clicks while a request is pending", async () => {
  const pending = deferred();
  const harness = await loadDashboard([response(runView()), pending.promise]);
  await connect(harness);

  const first = harness.elements["approve-button"].click();
  const duplicate = harness.elements["approve-button"].click();
  await settle();
  assert.equal(harness.calls.filter((call) => call.options.method === "POST").length, 1);
  pending.resolve(response(runView({ hash: HASH_B, status: "approved" })));
  await Promise.all([first, duplicate]);
});

test("an absent or invalid connected plan hash locks governance without a POST", async () => {
  for (const hash of [null, "not-a-hash", "A".repeat(64)]) {
    const harness = await loadDashboard([response(runView({ hash }))]);
    await connect(harness);
    assert.equal(harness.calls.filter((call) => call.options.method === "POST").length, 0);
    assert.equal(harness.elements["mode-notice"].dataset.mode, "unavailable");
    assert.equal(harness.elements["live-controls"].hidden, true);
  }
});

test("typed LLM states render distinct bounded copy without provider or model text", async () => {
  const cases = [
    ["available", "Available · cited advisory digest recorded", "available"],
    ["unavailable", "Unavailable · deterministic fallback", "unavailable"],
    ["timeout", "Timed out · deterministic fallback", "timeout"],
    ["invalid_output", "Invalid output · rejected; deterministic fallback", "invalid_output"],
    ["malformed", "Invalid output · rejected; deterministic fallback", "invalid_output"],
    ["uncited", "Uncited output · rejected; deterministic fallback", "uncited"],
  ];

  for (const [status, copy, renderedStatus] of cases) {
    const harness = await loadDashboard([response(runView({ llmStatus: status }))]);
    await connect(harness);
    assert.equal(harness.elements["llm-copy"].textContent, copy);
    assert.equal(harness.elements["llm-status"].dataset.status, renderedStatus);
    assert.doesNotMatch(harness.elements["llm-copy"].textContent, /provider\/model|must-not-render/i);
  }
});

test("ephemeral token is never rendered, persisted, placed in URLs, or sent in bodies", async () => {
  const token = "never-render-this-token";
  const harness = await loadDashboard([response(runView())]);
  await connect(harness, token);
  const rendered = Object.values(harness.elements).map((node) => `${node.textContent}${node.href}${node.value}`).join(" ");
  assert.doesNotMatch(rendered, new RegExp(token));
  assert.ok(harness.calls.every((call) => !String(call.url).includes(token)));
  assert.ok(harness.calls.every((call) => !String(call.options.body || "").includes(token)));
  assert.ok(harness.calls.every((call) => call.options.headers.Authorization === `Bearer ${token}`));
});

test("audit inspection uses the ephemeral bearer and renders only a bounded safe summary", async () => {
  const token = "audit-view-token-must-not-render";
  const secret = "audit-payload-secret-must-not-render";
  const harness = await loadDashboard([
    response(runView()),
    response({
      run_id: "018f0000-0000-7000-8000-000000000901",
      events: [
        { sequence: 1, event_type: "prototype.run.created", public_payload: { secret } },
        { sequence: 2, event_type: "prototype.plan.prepared", public_payload: {} },
      ],
    }),
  ]);
  await connect(harness, token);

  await harness.elements["audit-link"].click();
  await settle();

  assert.equal(
    harness.calls[1].url,
    "/api/v1/prototype/runs/018f0000-0000-7000-8000-000000000901/trace",
  );
  assert.equal(harness.calls[1].options.headers.Authorization, `Bearer ${token}`);
  assert.equal(harness.elements["audit-result"].textContent, "2 integrity-chained run events available.");
  const rendered = Object.values(harness.elements).map((node) => `${node.textContent}${node.href}${node.value}`).join(" ");
  assert.doesNotMatch(rendered, new RegExp(token));
  assert.doesNotMatch(rendered, new RegExp(secret));
  assert.ok(harness.calls.every((call) => !String(call.url).includes(token)));
});
