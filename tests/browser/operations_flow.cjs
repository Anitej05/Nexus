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
      throw new Error(`Owned operations server did not start: ${server.startError || logs()}`);
    }
    try {
      const response = await fetch(`${origin}/health/live`, { signal: AbortSignal.timeout(1000) });
      if (response.ok) return;
    } catch {}
    await delay(150);
  }
  throw new Error(`Owned operations server health timed out: ${logs()}`);
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

// Browser plugin not available. Exercise the real application with Playwright.
// Optional OPERATIONS_BASE_URL points at a separately owned PostgreSQL-backed server.
async function main() {
  const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'nexus-operations-browser-'));
  let server,browser,logs='';
  const database=process.env.NEXUS_OPERATIONS_BROWSER_DATABASE_URL||path.join(temporary,'operations.sqlite3');
  const port=await freePort();
  const origin=process.env.OPERATIONS_BASE_URL||`http://127.0.0.1:${port}`;
  async function start(){
    server=spawn('uv',['run','--frozen','--no-sync','python','scripts/run_operations.py','--port',String(port),'--database',database],{cwd:root,windowsHide:true,detached:process.platform!=='win32',stdio:['ignore','pipe','pipe']});
    server.on('error',error=>server.startError=error.message);
    const retain=chunk=>logs=(logs+chunk.toString()).slice(-12000);
    server.stdout.on('data',retain);server.stderr.on('data',retain);
    await waitHealthy(server,origin,()=>logs);
  }
  try {
    if(!process.env.OPERATIONS_BASE_URL)await start();
    browser=await chromium.launch({headless:true});
    const page=await browser.newPage({viewport:{width:1440,height:1080}});
    page.setDefaultTimeout(20000);
    const errors=[];
    page.on('pageerror',error=>errors.push(error.message));
    page.on('console',message=>{if(message.type()==='error')errors.push(message.text())});
    const waitStatus=async (phrase,timeout=20000)=>{await page.waitForFunction(value=>document.querySelector('#status').textContent.includes(value)||document.querySelector('#status').classList.contains('error'),phrase,{timeout});assert.ok((await page.locator('#status').textContent()).includes(phrase),await page.locator('#status').textContent())};
    const mutation=async(pathname,operation)=>{const response=page.waitForResponse(r=>new URL(r.url()).pathname===pathname&&r.request().method()!=='GET');await operation();const r=await response;assert.ok(r.ok(),`${r.status()} ${await r.text()}`);return r.json()};
    async function login(username,password){await page.fill('#username',username);await page.fill('#password',password);await page.click('#auth-submit');await waitStatus('Signed in securely')}
    async function choose(id){await page.selectOption('#workspace-select',id);await waitStatus('Workspace loaded')}
    await page.goto(origin+'/operations');
    assert.match(await page.title(),/NEXUS.*Operations/);
    await page.keyboard.press('Tab');assert.equal(await page.locator('.skip').evaluate(n=>n===document.activeElement),true);
    await waitStatus('Set up');
    await login('operations-owner','OwnerPass!2026');
    await page.locator('#user-admin summary').click();
    await page.fill('#new-username','independent-reviewer');await page.fill('#new-password','ReviewerPass!2026');
    await page.selectOption('#new-role','approver');await page.locator('#user-form button').click();await waitStatus('Account created');
    if(!await page.locator('summary').filter({hasText:'Create workspace'}).evaluate(n=>n.parentElement.open))await page.locator('summary').filter({hasText:'Create workspace'}).click();
    await page.fill('#workspace-name','Construction delivery plan');
    const created=await mutation('/api/v1/operations/workspaces',()=>page.locator('#workspace-form button').click());
    const workspaceId=created.id;
    await waitStatus('Workspace loaded');
    await page.click('#sample');await waitStatus('Dataset version persisted');
    assert.match(await page.locator('#lineage').textContent(),/synthetic/i);
    // Save a real JSON file, import it through the actual file input, and observe its provenance.
    const dataset=JSON.parse(await page.locator('#dataset-editor').inputValue());
    const imported=path.join(temporary,'construction-user.json');await fs.writeFile(imported,JSON.stringify(dataset));
    await page.setInputFiles('#upload-file',imported);await page.click('#upload');await waitStatus('Dataset version persisted');
    assert.match(await page.locator('#lineage').textContent(),/construction-user.json/);
    const bundle=path.join(root,'tests/fixtures/operations_engine_construction_sample');await page.setInputFiles('#upload-file',(await fs.readdir(bundle)).filter(name=>/\.(csv|json)$/.test(name)).map(name=>path.join(bundle,name)));await page.click('#upload');await waitStatus('Dataset version persisted');assert.match(await page.locator('#lineage').textContent(),/tasks.csv/);
    await page.click('#analyze');await waitStatus('Forecast recomputed');
    assert.match(await page.locator('#metrics').textContent(),/P50 completion/);
    assert.ok(await page.locator('#graph svg circle').count()>0);
    assert.ok(await page.locator('#schedule tr').count()>1);
    const resource=dataset.resources[0];
    await page.fill('#scenario-changes',JSON.stringify([{path:`/resources/${resource.id}/capacity`,value:resource.capacity+1}]));
    await page.locator('#scenario-form button').click();await waitStatus('Branch modelled');
    assert.match(await page.locator('#scenarios').textContent(),/comparison/);
    await page.locator('#scenarios button').first().click();await waitStatus('Branch proposed');
    assert.equal(await page.getByRole('button',{name:'Approve branch',exact:true}).isDisabled(),true);
    await page.click('#logout');await waitStatus('Signed out');
    await login('independent-reviewer','ReviewerPass!2026');await choose(workspaceId);
    assert.equal(await page.getByRole('button',{name:'Apply approved branch',exact:true}).isDisabled(),true);
    await page.getByRole('button',{name:'Approve branch',exact:true}).click();await waitStatus('Exact plan hash approved');
    await page.click('#logout');await waitStatus('Signed out');
    await login('operations-owner','OwnerPass!2026');await choose(workspaceId);
    await page.getByRole('button',{name:'Apply approved branch',exact:true}).click();await waitStatus('Approved branch applied');
    const applied=JSON.parse(await page.locator('#dataset-editor').inputValue());assert.equal(applied.resources[0].capacity,resource.capacity+1);
    let revision=await page.locator('#revision').textContent();
    if(process.env.NEXUS_OPERATIONS_LIVE_WEATHER==='1'){await page.fill('#latitude','13.08');await page.fill('#longitude','80.27');await page.locator('#weather-form button').click();await waitStatus('Weather observation fetched');const weather=JSON.parse(await page.locator('#weather').textContent());assert.equal(weather.source,'Open-Meteo');assert.equal(weather.daily.time.length,7)}
    if(process.env.NEXUS_OPERATIONS_LIVE_ADVICE==='1'){
      await page.click('#models-load');await page.waitForFunction(()=>document.querySelector('#status').textContent.includes('model catalog loaded'),{},{timeout:60000});
      assert.match(await page.locator('#models').textContent(),/nvidia\/nemotron-3-ultra-550b-a55b/);
      await page.fill('#advice-question','Summarize the computed forecast and the single most useful feasible capacity alternative. Cite exact graph IDs. Do not invent shortages.');
      const pending=page.waitForResponse(r=>new URL(r.url()).pathname.endsWith('/integrations/advice'),{timeout:110000});
      await page.locator('#advice-form button').click();const response=await pending;
      assert.ok(response.ok(),`${response.status()} ${await response.text()}`);
      const advice=await response.json();assert.equal(advice.model,'nvidia/nemotron-3-ultra-550b-a55b');assert.ok(advice.evidence_ids.length);
      await waitStatus('Advisory response received');
      console.log(JSON.stringify({liveAdvisor:advice.model,evidenceIds:advice.evidence_ids,answer:advice.answer}));
    }
    await page.click('#learning-sample');await waitStatus('historical outcomes imported',90000);
    let activeModel=JSON.parse(await page.locator('#learning-model').textContent());assert.ok(activeModel.id,'Automatic training must promote an evaluated model on the labelled synthetic fixture');
    const historyResponse=await page.request.get(origin+'/api/v1/operations/domains/construction/history-sample');assert.ok(historyResponse.ok());const history=await historyResponse.json();const historicalFile=path.join(temporary,'synthetic-historical-outcomes.json');await fs.writeFile(historicalFile,JSON.stringify(history.history||history));
    await page.setInputFiles('#learning-file',historicalFile);await page.selectOption('#learning-mode','replace');await page.click('#learning-import');await waitStatus('historical outcomes imported',90000);activeModel=JSON.parse(await page.locator('#learning-model').textContent());assert.ok(activeModel.id);assert.equal(activeModel.history_kind,'synthetic');assert.ok(Number.isFinite(activeModel.metrics.test.duration.mae));assert.ok(Number.isFinite(activeModel.metrics.validation.baseline.duration.mae));assert.ok(activeModel.split.row_counts.test>0);assert.ok(activeModel.training_digest);
    const beforeLearnedPlan=JSON.parse(await page.locator('#dataset-editor').inputValue());await page.click('#learning-scenario');await waitStatus('Learned duration branch modelled');
    assert.match(await page.locator('#scenarios').textContent(),/Learned duration branch/);
    await page.locator('#scenarios button').last().click();await waitStatus('Branch proposed');
    await page.click('#logout');await waitStatus('Signed out');await login('independent-reviewer','ReviewerPass!2026');await choose(workspaceId);
    await page.getByRole('button',{name:'Approve branch',exact:true}).last().click();await waitStatus('Exact plan hash approved');
    await page.click('#logout');await waitStatus('Signed out');await login('operations-owner','OwnerPass!2026');await choose(workspaceId);
    await page.getByRole('button',{name:'Apply approved branch',exact:true}).last().click();await waitStatus('Approved branch applied');revision=await page.locator('#revision').textContent();const learnedPlan=JSON.parse(await page.locator('#dataset-editor').inputValue());assert.ok(learnedPlan.tasks.some((task,index)=>task.duration_estimate!==beforeLearnedPlan.tasks[index].duration_estimate),'Approved model branch stores learned duration estimates');for(const task of learnedPlan.tasks){const before=beforeLearnedPlan.tasks.find(item=>item.id===task.id);assert.equal(task.productivity,before.productivity,'Inference preserves actual productivity');if((task.remaining_quantity??task.quantity)>0){assert.ok(Number.isFinite(task.duration_estimate));assert.equal(task.estimate_quantity,task.remaining_quantity??task.quantity,'Estimate records its quantity basis')}}
    await page.locator('#learning').screenshot({path:path.join(temporary,'operations-learning.png')});await page.locator('#learning summary').filter({hasText:'Active model metrics'}).click();await page.locator('#learning').screenshot({path:path.join(temporary,'operations-learning-metrics.png')});await page.locator('#learning summary').filter({hasText:'Active model metrics'}).click();
    await page.screenshot({path:path.join(temporary,'operations-desktop.png'),fullPage:true});await page.evaluate(()=>scrollTo(0,0));await page.screenshot({path:path.join(temporary,'operations-desktop-viewport.png')});
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'No mobile page overflow');
    await page.screenshot({path:path.join(temporary,'operations-mobile.png'),fullPage:true});await page.evaluate(()=>scrollTo(0,0));await page.screenshot({path:path.join(temporary,'operations-mobile-viewport.png')});
    await page.setViewportSize({width:1440,height:1080});
    await page.locator('summary').filter({hasText:'Update observed progress'}).click();
    const observed=JSON.parse(await page.locator('#dataset-editor').inputValue());observed.tasks[0].remaining_quantity=0;
    await page.fill('#dataset-editor',JSON.stringify(observed));await page.click('#save-dataset');await waitStatus('Dataset version persisted');
    await page.click('#analyze');await waitStatus('Forecast recomputed');assert.equal(JSON.parse(await page.locator('#dataset-editor').inputValue()).tasks[0].remaining_quantity,0);revision=await page.locator('#revision').textContent();
    if(!await page.locator('summary').filter({hasText:'Create workspace'}).evaluate(n=>n.parentElement.open))await page.locator('summary').filter({hasText:'Create workspace'}).click();
    await page.fill('#workspace-name','Manufacturing capacity plan');await page.selectOption('#domain','manufacturing');
    await page.locator('#workspace-form button').click();await waitStatus('Workspace loaded');
    await page.click('#sample');await waitStatus('Dataset version persisted');
    await page.click('#analyze');await waitStatus('Forecast recomputed');
    assert.match(await page.locator('#revision').textContent(),/manufacturing/);
    const manufacturing=JSON.parse(await page.locator('#dataset-editor').inputValue());const defaultChanges=JSON.parse(await page.locator('#scenario-changes').inputValue());assert.equal(defaultChanges[0].path,`/resources/${manufacturing.resources[0].id}/capacity`);await page.locator('#scenario-form button').click();await waitStatus('Branch modelled');assert.equal(await page.locator('#scenarios button').count(),1);
    if(!process.env.OPERATIONS_BASE_URL){await stopOwnedServer(server);await start();await page.reload();await waitStatus('Session ready');if(await page.locator('#auth').isVisible())await login('operations-owner','OwnerPass!2026');await choose(workspaceId);assert.equal(await page.locator('#revision').textContent(),revision);assert.equal(JSON.parse(await page.locator('#dataset-editor').inputValue()).resources[0].capacity,resource.capacity+1);assert.equal(JSON.parse(await page.locator('#learning-model').textContent()).id,activeModel.id,'Promoted training artifact persists across server restart');const persistedPlan=JSON.parse(await page.locator('#dataset-editor').inputValue());const inferred=await mutation(`/api/v1/operations/workspaces/${workspaceId}/learning/scenarios`,()=>page.click('#learning-scenario'));await waitStatus('Learned duration branch modelled');assert.equal(inferred.model_metadata.id,activeModel.id,'Restarted server performs inference using persisted model weights');assert.ok(inferred.model_metadata.predictions.length>0);for(const task of inferred.payload.tasks){const before=persistedPlan.tasks.find(item=>item.id===task.id);assert.equal(task.productivity,before.productivity);if((task.remaining_quantity??task.quantity)>0){assert.ok(Number.isFinite(task.duration_estimate));assert.equal(task.estimate_quantity,task.remaining_quantity??task.quantity)}}}
    assert.equal(await page.locator('nextjs-portal,vite-error-overlay,#webpack-dev-server-client-overlay').count(),0);
    assert.deepEqual(errors,[]);
    console.log(JSON.stringify({passed:true,origin,viewports:[1440,390],evidence:temporary,persistence:!process.env.OPERATIONS_BASE_URL}));
  }finally{if(browser)await browser.close();if(server)await stopOwnedServer(server)}
}
main().catch(error=>{console.error(error);process.exitCode=1});
