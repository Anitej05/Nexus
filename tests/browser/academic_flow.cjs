"use strict";

// Starts an isolated real application; no Docker, remote service or shared server.
const assert = require("node:assert/strict");
const { spawn, spawnSync } = require("node:child_process");
const fs = require("node:fs/promises");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const root = path.resolve(__dirname, "../..");
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function freePort() {
  const reservation = net.createServer();
  await new Promise((resolve, reject) => {
    reservation.once("error", reject);
    reservation.listen(0, "127.0.0.1", resolve);
  });
  const port = reservation.address().port;
  await new Promise((resolve, reject) => reservation.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function waitHealthy(server, origin, logs) {
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    if (server.exitCode !== null || server.startError) {
      throw new Error(`Owned demo server did not start: ${server.startError || logs()}`);
    }
    try {
      const response = await fetch(`${origin}/health/live`, { signal: AbortSignal.timeout(1000) });
      if (response.ok) return;
    } catch {}
    await delay(150);
  }
  throw new Error(`Owned demo server health timed out: ${logs()}`);
}

async function stopOwnedServer(server) {
  if (!server?.pid || server.exitCode !== null) return;
  // uv can own a Python child on Windows. Target only this invocation's PID tree.
  if (process.platform === "win32") {
    const result = spawnSync("taskkill", ["/PID", String(server.pid), "/T", "/F"], { windowsHide: true, encoding: "utf8" });
    if (result.status !== 0 && server.exitCode === null) throw new Error("Could not stop owned demo server process tree");
  } else {
    try { process.kill(-server.pid, "SIGTERM"); } catch (error) { if (error.code !== "ESRCH") throw error; }
  }
  for (let attempt = 0; attempt < 30 && server.exitCode === null; attempt += 1) await delay(100);
  if (process.platform !== "win32" && server.exitCode === null) {
    try { process.kill(-server.pid, "SIGKILL"); } catch (error) { if (error.code !== "ESRCH") throw error; }
  }
}

async function main() {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), "nexus-academic-browser-"));
  let server;
  let browser;
  let logs = "";
  try {
    const port = await freePort();
    const origin = `http://127.0.0.1:${port}`;
    server = spawn("uv", ["run", "--frozen", "--no-sync", "python", "scripts/run_academic_demo.py", "--port", String(port), "--database", path.join(temporary, "demo.sqlite3")], {
      cwd: root, windowsHide: true, detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"],
    });
    server.on("error", (error) => { server.startError = error.message; });
    const retainLogs = (chunk) => { logs = (logs + chunk.toString()).slice(-12_000); };
    server.stdout.on("data", retainLogs);
    server.stderr.on("data", retainLogs);
    await waitHealthy(server, origin, () => logs);
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1080 } });
    page.setDefaultTimeout(15_000);
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => { if (["error", "warning"].includes(message.type())) errors.push(message.text()); });
    page.on("response", (response) => { if (response.status() >= 400) errors.push(`HTTP ${response.status()} ${new URL(response.url()).pathname}`); });
    await page.goto(`${origin}/prototype`);
    await page.keyboard.press("Tab");
    assert.equal(await page.locator(".skip").evaluate((node) => document.activeElement === node), true, "Keyboard users can focus the skip link");
    assert.equal(page.url(), `${origin}/prototype`);
    assert.match(await page.title(), /NEXUS/);
    assert.match(await page.locator("h1").innerText(), /Operational Shift/);
    assert.equal(await page.locator("nextjs-portal, vite-error-overlay, #webpack-dev-server-client-overlay").count(), 0);
    await page.waitForSelector("#demo-identity:not([hidden])");
    await page.selectOption("#demo-identity", { label: "Analyst / proposer · proposer" });
    await page.waitForFunction(() => document.querySelector("#scenario-select").options.length === 4);
    const snapshots = [];
    const live = () => page.waitForFunction(() => document.querySelector("#mode-notice").dataset.mode === "live");
    const state = (expected) => page.waitForFunction((value) => document.querySelector("#top-state").textContent === value, expected);
    for (const scenario of ["storm-and-checkout-shift-v1", "supply-heavy-v1"]) {
      await page.selectOption("#scenario-select", scenario);
      const created = page.waitForResponse((response) => response.url() === `${origin}/api/v1/prototype/runs` && response.request().method() === "POST");
      await page.click("#create-button");
      const createdResponse = await created;
      assert.equal(createdResponse.status(), 201);
      const initial = await createdResponse.json();
      assert.equal(initial.scenario_id, scenario);
      await live(); await state("Awaiting approval");
      await page.selectOption("#demo-identity", { label: "Independent approver · approver" });
      await live();
      await page.click("#approve-button"); await state("Approved");
      await page.selectOption("#demo-identity", { label: "Analyst / proposer · proposer" });
      await live();
      const executed = page.waitForResponse((response) => response.url().endsWith(`/runs/${initial.run_id}/execute`) && response.request().method() === "POST");
      await page.click("#execute-button");
      const executionResponse = await executed;
      assert.equal(executionResponse.status(), 200);
      const completed = await executionResponse.json();
      await state("Verified");
      assert.equal(completed.verification.baseline_delay_hours - completed.verification.observed_delay_hours, completed.verification.delay_reduction_hours);
      assert.equal(completed.verification.delay_reduction_hours, completed.plan.expected_delay_reduction_hours);
      assert.match(await page.locator("#verification-copy").innerText(), new RegExp(`reduction ${completed.verification.delay_reduction_hours}h`));
      assert.match(await page.locator("#plan-options").innerText(), /no_action: projected final delay/);
      assert.match(await page.locator("#plan-options").innerText(), /simulated_reroute: projected final delay/);
      await page.click("#audit-link");
      await page.waitForFunction(() => document.querySelector("#trace-content").textContent.includes("prototype.verification.completed"));
      assert.equal(await page.locator("#audit-result").innerText(), "11 integrity-chained run events available.");
      assert.equal(await page.locator("#graph-scroll svg.live-graph").count(), 1);
      assert.match(await page.locator("#graph-relationships").textContent(), /Relationships/);
      assert.equal(await page.locator("#mode-title").innerText(), "Local academic run connected");
      await page.locator("#trace-details summary").click();
      assert.equal(await page.locator("#trace-content").isVisible(), true);
      assert.equal(await page.locator("#scenario-name").innerText(), scenario);
      snapshots.push({ scenario, run: initial.run_id, scores: completed.signals.map((signal) => signal.score), reduction: completed.verification.delay_reduction_hours });
    }
    assert.notEqual(snapshots[0].run, snapshots[1].run);
    assert.notDeepEqual(snapshots[0].scores, snapshots[1].scores);
    assert.notEqual(snapshots[0].reduction, snapshots[1].reduction);
    assert.deepEqual(snapshots.map((value) => value.reduction), [14, 24]);
    const screenshots = process.env.NEXUS_BROWSER_ARTIFACT_DIR ? path.resolve(process.env.NEXUS_BROWSER_ARTIFACT_DIR) : temporary;
    await fs.mkdir(screenshots, { recursive: true });
    for (const viewport of [{ width: 1440, height: 1080 }, { width: 390, height: 844 }]) {
      await page.setViewportSize(viewport);
      await page.evaluate(() => window.scrollTo(0, 0));
      const dimensions = await page.evaluate(() => ({ viewport: innerWidth, content: document.documentElement.scrollWidth }));
      assert.ok(dimensions.content <= dimensions.viewport + 1, `Horizontal overflow at ${viewport.width}px: ${JSON.stringify(dimensions)}`);
      assert.equal(await page.locator("#verification-title").isVisible(), true);
      await page.screenshot({ path: path.join(screenshots, `academic-${viewport.width}.png`), fullPage: true });
    }
    assert.deepEqual(errors, [], "Browser console, runtime and HTTP checks");
    console.log(JSON.stringify({ result: "PASS", scenarios: snapshots, viewports: [1440, 390], browserErrors: errors.length, screenshots: process.env.NEXUS_BROWSER_ARTIFACT_DIR ? screenshots : "temporary (cleaned after test)" }, null, 2));
  } finally {
    try { if (browser) await browser.close(); } finally {
      try { await stopOwnedServer(server); } finally { await fs.rm(temporary, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
    }
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
