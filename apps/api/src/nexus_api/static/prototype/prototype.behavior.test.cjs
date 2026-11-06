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
    this.children = [];
  }

  get textContent() { return this._textContent + (this.children || []).map(node => node.textContent).join(""); }
  set textContent(value) { this._textContent = String(value); this.children = []; }
  appendChild(node) { this.children.push(node); if (!this.value && node.value) this.value = node.value; }
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
  for (let index = 0; index < 20; index += 1) await Promise.resolve();
};

const loadDashboard = async (queuedResponses, search = "?run=018f0000-0000-7000-8000-000000000901", optional = {}) => {
  const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
  const elements = Object.fromEntries(ids.map((id) => [id, new FakeElement(id)]));
  const preview = html.match(/<script id="prototype-preview" type="application\/json">([\s\S]*?)<\/script>/);
  assert.ok(preview);
  elements["prototype-preview"].textContent = preview[1];
  const calls = [];
  const optionalCalls = [];
  const queue = [...queuedResponses];
  const fetch = (url, options = {}) => {
    if (url.endsWith("/scenarios")) optionalCalls.push({url,options});
    if (!url.endsWith("/demo-session") && !url.endsWith("/scenarios") && !url.endsWith("/graph")) calls.push({ url, options });
    if (url.endsWith("/demo-session") || url.endsWith("/scenarios") || url.endsWith("/graph")) return Promise.resolve(optional[url] || response({}, false));
    const next = queue.shift();
    if (next === undefined) throw new Error(`Unexpected fetch: ${url}`);
    return Promise.resolve(next);
  };
  const document = {
    createElement: () => new FakeElement("generated"),
    createElementNS: (namespace, tag) => new FakeElement(tag),
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
  return { calls, elements, optionalCalls };
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


test("connected analytical content uses returned evidence and actual simulation outcome", async () => {
  const value = runView({status:"verified"});
  value.scenario_id = "quiet-shift-v1";
  value.signals = [{domain:"supply",score:0.23,threshold:0.8,model_version:"rules.v2",target_id:"shipment-new",feature_map:{port_closed:0},evidence_node_ids:["port-new"]}];
  value.findings = [{agent_role:"supply_risk_analyst",finding_code:"below_threshold",uncertainty_code:"Synthetic evidence",evidence_node_ids:["port-new"]}];
  value.llm.summary = "<script>plain advisory</script>";
  value.plan.target_id = "shipment-new"; value.plan.destination = "sim://new"; value.plan.expected_delay_reduction_hours = 3; value.plan.options = [{option_id:"reroute",projected_delay_hours:6,delay_reduction_hours:3},{option_id:"wait",projected_delay_hours:9,delay_reduction_hours:0}];
  value.verification = {baseline_delay_hours:9,observed_delay_hours:6,delay_reduction_hours:3};
  const harness = await loadDashboard([response(value)]);
  await connect(harness);
  assert.match(harness.elements["signals-content"].textContent,/0.23/);
  assert.match(harness.elements["findings-content"].textContent,/below_threshold/);
  assert.equal(harness.elements["advisory-summary"].textContent,value.llm.summary);
  assert.match(harness.elements["verification-copy"].textContent,/9h.*6h.*3h/);
  assert.match(harness.elements["plan-options"].textContent,/reroute: projected final delay 6h; reduction 3h/);
  assert.match(harness.elements["plan-options"].textContent,/wait: projected final delay 9h; reduction 0h/);
  assert.doesNotMatch(harness.elements["verification-copy"].textContent,/14/);
});

test("create run submits the selected scenario and disconnect clears authority", async () => {
  const harness = await loadDashboard([response(runView())], "");
  harness.elements["bearer-token"].value = "create-token";
  harness.elements["scenario-select"].value = "quiet-shift-v1";
  await harness.elements["create-button"].click(); await settle();
  assert.equal(harness.calls[0].url,"/api/v1/prototype/runs");
  assert.equal(JSON.parse(harness.calls[0].options.body).scenario_id,"quiet-shift-v1");
  await harness.elements["disconnect-button"].click();
  assert.equal(harness.elements["live-controls"].hidden,true);
  assert.equal(harness.elements["bearer-token"].value,"");
});


test("local identities stay in memory, switch authority and reload persisted run", async () => {
  const harness = await loadDashboard([response(runView()), response(runView({status:"approved"}))], "?run=run-one", {
    "/api/v1/prototype/scenarios":response({scenarios:[{scenario_id:"quiet",title:"Quiet shift",description:"Synthetic control"}]}),
    "/api/v1/prototype/demo-session":response({mode:"academic_local",identities:[{label:"Analyst",role:"proposer",token:"local-proposer"},{label:"Approver",role:"approver",token:"local-approver"}]}),
    "/api/v1/prototype/runs/018f0000-0000-7000-8000-000000000901/graph":response({seed_digest:"digest",nodes:[{id:"fresh",type:"port",label:"Fresh evidence"}],edges:[]}),
  });
  const select = harness.elements["demo-identity"];
  assert.equal(select.hidden,false);
  select.value = "0"; await select.listeners.get("change")(); await settle();
  assert.equal(harness.calls[0].options.headers.Authorization,"Bearer local-proposer");
  assert.equal(harness.elements["scenario-select"].children[0].textContent,"Quiet shift");
  assert.match(harness.elements["graph-scroll"].textContent,/Fresh evidence/);
  select.value = "1"; await select.listeners.get("change")(); await settle();
  assert.equal(harness.calls[1].options.headers.Authorization,"Bearer local-approver");
  assert.ok(harness.optionalCalls.some(x => x.options.headers?.Authorization === "Bearer local-proposer"));
  assert.ok(harness.optionalCalls.some(x => x.options.headers?.Authorization === "Bearer local-approver"));
  assert.equal(harness.elements["top-state"].textContent,"Approved");
  assert.ok(select.children.every(x => !x.value.includes("local-")));
});



test("disconnect invalidates a pending connection response", async () => {
  const pending = deferred(); const h = await loadDashboard([pending.promise]);
  h.elements["bearer-token"].value = "old-token"; const connecting = h.elements["connect-button"].click(); await settle();
  await h.elements["disconnect-button"].click(); pending.resolve(response(runView())); await connecting; await settle();
  assert.equal(h.elements["mode-notice"].dataset.mode,"unavailable");
  assert.equal(h.elements["live-controls"].hidden,true);
});

test("new connection wins over an old pending mutation", async () => {
  const pending = deferred(); const h = await loadDashboard([response(runView()),pending.promise,response(runView({hash:HASH_B,status:"rejected"}))]); await connect(h);
  const mutation = h.elements["approve-button"].click(); await settle();
  h.elements["run-reference"].value = "new-run"; await h.elements["connect-button"].click();
  pending.resolve(response(runView({status:"approved"}))); await mutation; await settle();
  assert.equal(h.elements["plan-hash"].textContent,HASH_B); assert.equal(h.elements["top-state"].textContent,"Rejected");
});

test("clear invalidates pending create and permits a fresh identity", async () => {
  const pending = deferred(); const h = await loadDashboard([pending.promise],"");
  h.elements["bearer-token"].value = "creator"; const creating = h.elements["create-button"].click(); await settle();
  await h.elements["disconnect-button"].click(); pending.resolve(response(runView())); await creating; await settle();
  assert.equal(h.elements["mode-notice"].dataset.mode,"unavailable"); assert.equal(h.elements["create-button"].disabled,false);
});


test("identity switch rejects stale graph responses", async () => {
  const graph = deferred();
  const h = await loadDashboard([response(runView()),response(runView({hash:HASH_B,status:"approved"}))],"?run=run-one",{
    "/api/v1/prototype/demo-session":response({mode:"academic_local",identities:[{label:"Proposer",role:"proposer",token:"first"},{label:"Approver",role:"approver",token:"second"}]}),
    "/api/v1/prototype/runs/018f0000-0000-7000-8000-000000000901/graph":graph.promise,
  });
  const select=h.elements["demo-identity"]; select.value="0";const first=select.listeners.get("change")();await settle();
  select.value="1";const second=select.listeners.get("change")();await settle();
  await h.elements["disconnect-button"].click();
  graph.resolve(response({seed_digest:"stale",nodes:[{id:"stale",type:"port",label:"stale forbidden evidence"}],edges:[]}));
  await first;await second;await settle();
  assert.doesNotMatch(h.elements["graph-scroll"].textContent,/stale forbidden evidence/);
  assert.equal(h.elements["mode-notice"].dataset.mode,"unavailable");
});

test("connecting a new run invalidates an older pending creation", async () => {
  const pending=deferred();const h=await loadDashboard([pending.promise,response(runView({hash:HASH_B,status:"rejected"}))],"");
  h.elements["bearer-token"].value="creator"; const creating=h.elements["create-button"].click();await settle();
  h.elements["run-reference"].value="other-run";await h.elements["connect-button"].click();
  pending.resolve(response(runView()));await creating;await settle();
  assert.equal(h.elements["plan-hash"].textContent,HASH_B);assert.equal(h.elements["top-state"].textContent,"Rejected");
});


test("live graph renders returned typed nodes, safe labels and numeric facts as SVG", async () => {
  const graph = {seed_digest:"fresh",nodes:[{id:"port-new",type:"Port",label:"<script>plain label</script>"},{id:"measurement",type:"ScenarioInput",label:"Baseline delay hours: 48"}],edges:[]};
  const h=await loadDashboard([response(runView())],"?run=run-one",{"/api/v1/prototype/runs/018f0000-0000-7000-8000-000000000901/graph":response(graph)});
  await connect(h);
  const svg=h.elements["graph-scroll"].children[0];
  assert.equal(svg.id,"svg"); assert.equal(svg.getAttribute("class"),"live-graph");
  assert.match(svg.textContent,/<script>plain label<\/script>/);
  assert.match(svg.textContent,/Baseline delay hours: 48/);
  assert.match(h.elements["graph-relationships"].textContent,/port-new/);
  assert.equal(h.elements["graph-accessible"].hidden,false);
});
