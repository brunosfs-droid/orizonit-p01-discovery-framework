// Actual Chromium flow/DOM/responsive checks; data fixture is synthetic, no DB.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawn} = require('node:child_process');
const {spawnSync} = require('node:child_process');
const {once} = require('node:events');
const readline = require('node:readline');
const {chromium} = require(process.env.CANCA_PLAYWRIGHT_MODULE || 'playwright');

(async () => {
  const fixture = spawn(process.env.CANCA_BROWSER_PYTHON || 'python', [path.join(__dirname, 'operator_web_browser_fixture.py')], {stdio:['ignore','pipe','pipe']});
  const lines = readline.createInterface({input:fixture.stdout});
  let browser;
  const readyTimeout = setTimeout(() => fixture.kill('SIGINT'), 20000);
  try {
    const [line] = await Promise.race([once(lines, 'line'), once(fixture, 'exit').then(() => { throw new Error('browser fixture exited before ready'); })]);
    clearTimeout(readyTimeout);
    const url = JSON.parse(line).url;
    browser = await chromium.launch({headless:true});
    const artifacts = process.env.CANCA_BROWSER_OUTPUT || path.join(__dirname, '../.web-ci-artifacts');
    fs.mkdirSync(artifacts, {recursive:true});
    for (const width of [1280, 390]) {
      const context = await browser.newContext({viewport:{width, height:900}});
      const page = await context.newPage(); const errors = [], external = [];
      page.on('pageerror', () => errors.push('pageerror'));
      page.on('request', request => { if (new URL(request.url()).origin !== new URL(url).origin) external.push('external-request'); });
      await page.goto(url); await page.getByRole('heading', {name:'Entrar na Cancã'}).waitFor();
      await page.screenshot({path:path.join(artifacts, `login-${width}.png`), fullPage:true});
      await page.getByLabel('Usuário', {exact:true}).fill('browser-reader');
      await page.getByLabel('Senha', {exact:true}).fill('Synthetic browser CI passphrase 01!');
      await page.getByRole('button', {name:'Entrar', exact:true}).click();
      await page.getByText('Informe o ID de um assessment autorizado.', {exact:true}).waitFor();
      assert.equal(await page.locator('#password').inputValue(), '');
      await page.getByLabel('ID do assessment', {exact:true}).fill('LAB-001');
      await page.getByLabel('Avaliações por página', {exact:true}).selectOption('1');
      await page.getByRole('button', {name:'Consultar', exact:true}).click();
      await page.getByText('Página 1 · 1 avaliação(ões)', {exact:true}).waitFor();
      assert.equal(await page.locator('#asset-count').innerText(), '1');
      assert.equal(await page.locator('#evaluation-count').innerText(), '4');
      assert.equal(await page.locator('#finding-count').innerText(), '2');
      assert.ok((await page.locator('#evaluations').innerText()).includes('<img src=x'));
      assert.equal(await page.locator('#evaluations img').count(), 0);
      assert.equal(await page.evaluate(() => window.cancaInjected), undefined);
      const firstFocus = await page.evaluate(() => document.activeElement.id);
      assert.equal(firstFocus, 'report-title');
      for (let number=2; number<=4; number++) {
        await page.getByRole('button', {name:'Próxima página', exact:true}).click();
        await page.getByText(`Página ${number} · 1 avaliação(ões)`, {exact:true}).waitFor();
      }
      assert.equal(await page.locator('#next-button').isDisabled(), true);
      await page.getByRole('button', {name:'Primeira página', exact:true}).click();
      await page.getByText('Página 1 · 1 avaliação(ões)', {exact:true}).waitFor();
      const downloadEvent = page.waitForEvent('download');
      await page.getByRole('button', {name:'Baixar relatório completo (ZIP)', exact:true}).click();
      const download = await downloadEvent;
      assert.equal(download.suggestedFilename(),'canca-LAB-001-report.zip');
      const archive = path.join(artifacts,`report-${width}.zip`);
      await download.saveAs(archive);
      await page.getByText('Relatório completo preparado para download.',{exact:true}).waitFor();
      assert.equal(await page.evaluate(()=>document.activeElement.id),'download-button');
      const verify=spawnSync(process.env.CANCA_BROWSER_PYTHON || 'python',[
        path.join(__dirname,'../docs/validation/VERIFY_OPERATOR_WEB_EXPORT_v0.6.13.py'),
        '--archive',archive,'--assessment-id','LAB-001','--evaluation-count','4','--finding-count','2'],{encoding:'utf8'});
      assert.equal(verify.status,0,verify.stdout+verify.stderr);
      assert.equal(JSON.parse(verify.stdout).files_verified,4);
      await page.screenshot({path:path.join(artifacts, `report-${width}.png`), fullPage:true});
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
      assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
      assert.deepEqual(await context.cookies(), []);
      await page.getByLabel('ID do assessment', {exact:true}).fill('LAB-OTHER');
      await page.getByRole('button', {name:'Consultar', exact:true}).click();
      await page.getByText('Sua conta não possui acesso a este assessment.', {exact:true}).waitFor();
      assert.equal(await page.locator('#report-panel').isVisible(), false);
      await page.getByRole('button', {name:'Sair', exact:true}).click();
      await page.getByRole('heading', {name:'Entrar na Cancã'}).waitFor();
      await page.reload(); await page.getByRole('heading', {name:'Entrar na Cancã'}).waitFor();
      assert.equal(await page.locator('#workspace').isVisible(), false);
      assert.deepEqual(errors, []); assert.deepEqual(external, []);
      await context.close();
    }
    console.log('OPERATOR WEB BROWSER PASS — Chromium desktop/mobile, complete ZIP/hash verification');
  } finally {
    clearTimeout(readyTimeout); if (browser) await browser.close(); lines.close();
    if (fixture.exitCode === null) { const exit = once(fixture, 'exit'); fixture.kill('SIGINT'); await exit; }
  }
})().catch(error => { console.error('OPERATOR WEB BROWSER FAILED', error); process.exitCode=1; });
