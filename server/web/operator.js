/* No cookies or persistent token storage. Report values enter the DOM as text. */
(() => {
  'use strict';
  const el = id => document.getElementById(id);
  let token = '', generation = 0, expiry = null, page = null, selection = null, busy = false;
  let grants = null;
  const pending = new Set();
  const downloads = new Set();
  const messages = {
    400: 'Confira o ID do assessment e os parâmetros da consulta.',
    401: 'Sessão encerrada ou expirada. Entre novamente.',
    403: 'Sua conta não possui acesso a este assessment.',
    404: 'Assessment não encontrado.',
    409: 'O escopo mudou. Consulte novamente a primeira página.',
    413: 'O relatório excede o limite de download de 32 MiB. Use a exportação local no servidor.',
    429: 'Limite de tentativas atingido. Aguarde antes de tentar novamente.',
    503: 'Serviço indisponível. Tente novamente em instantes.'
  };
  function message(text) { el('message').textContent = text; }
  function clearReport() {
    page = null; selection = null;
    el('report-panel').hidden = true;
    el('evaluations').replaceChildren();
    for (const id of ['report-title', 'lifecycle', 'asset-count', 'evaluation-count', 'finding-count', 'coverage', 'outcomes', 'scope', 'snapshot', 'page-label']) el(id).textContent = '';
  }
  function controls() {
    el('login-button').disabled = busy;
    el('report-button').disabled = busy;
    el('assessment').disabled = busy;
    el('page-size').disabled = busy;
    el('assessment-selector').disabled = busy || !grants || grants.length === 0;
    el('assessment-refresh-button').disabled = busy || !token;
    el('next-button').disabled = busy || !page || !page.has_more;
    el('restart-button').disabled = busy || !selection;
    el('download-button').disabled = busy || !page || !selection;
    el('executive-download-button').disabled = busy || !page || !selection;
  }
  function reset(text = '') {
    generation += 1;
    for (const request of pending) request.abort();
    pending.clear();
    for (const url of downloads) URL.revokeObjectURL(url);
    downloads.clear();
    clearTimeout(expiry); expiry = null;
    token = ''; busy = false;
    el('password').value = ''; el('username').value = ''; el('assessment').value = '';
    el('operator-name').textContent = '';
    clearAssessments();
    clearReport(); controls();
    el('workspace').hidden = true; el('login-panel').hidden = false;
    message(text);
  }
  async function request(path, options = {}, bearer = token, parse = response => response.json(), milliseconds = 12000) {
    const controller = new AbortController(); pending.add(controller);
    const timeout = setTimeout(() => controller.abort(), milliseconds);
    const headers = {...(options.headers || {})};
    if (bearer) headers.Authorization = 'Bearer ' + bearer;
    try {
      const response = await fetch(path, {...options, headers, signal: controller.signal,
        credentials: 'omit', cache: 'no-store', redirect: 'error', mode: 'same-origin'});
      if (!response.ok) {
        const body = await response.json();
        throw Object.assign(new Error('request_failed'), {status: response.status, code: body.error_code});
      }
      return await parse(response);
    } finally {
      controller.abort();
      clearTimeout(timeout); pending.delete(controller);
    }
  }
  async function download(kind = 'technical') {
    if (busy || !token || !page || !selection) return;
    const executive = kind === 'executive';
    const button = executive ? 'executive-download-button' : 'download-button';
    const label = executive ? 'executivo' : 'completo';
    const selected = selection, scope = page.report_scope_sha256, stamp = generation;
    const filename = 'canca-' + selected.assessment + (executive ? '-executive.zip' : '-report.zip');
    busy = true; controls(); message('Preparando relatório ' + label + '…');
    try {
      const blob = await request('/api/v1/assessments/' + encodeURIComponent(selected.assessment) +
        '/report/' + (executive ? 'executive/' : '') + 'export?' + new URLSearchParams({expected_scope_sha256: scope}), {}, token, async response => {
          const length = response.headers.get('Content-Length'), digest = response.headers.get('X-Canca-Export-SHA256');
          if (response.headers.get('Content-Type') !== 'application/zip' ||
              response.headers.get('Content-Disposition') !== 'attachment; filename="' + filename + '"' ||
              response.headers.get('X-Canca-Report-Scope-SHA256') !== scope ||
              !/^[0-9a-f]{64}$/.test(digest || '') || !/^[1-9][0-9]{0,8}$/.test(length || '') ||
              Number(length) > 32 * 1024**2 || !response.body) throw new Error('invalid_export');
          const data = new Uint8Array(Number(length)), reader = response.body.getReader();
          let offset = 0;
          while (true) {
            const {done, value} = await reader.read();
            if (done) break;
            if (offset + value.byteLength > data.byteLength) throw new Error('invalid_export');
            data.set(value, offset); offset += value.byteLength;
          }
          if (offset !== data.byteLength) throw new Error('invalid_export');
          const actual = [...new Uint8Array(await crypto.subtle.digest('SHA-256', data))]
            .map(byte => byte.toString(16).padStart(2, '0')).join('');
          if (actual !== digest) throw new Error('invalid_export');
          return new Blob([data], {type: 'application/zip'});
        }, 100000);
      if (stamp !== generation) return;
      const url = URL.createObjectURL(blob); downloads.add(url);
      const link = document.createElement('a'); link.href = url; link.download = filename;
      document.body.append(link);
      try { link.click(); } finally { link.remove(); }
      setTimeout(() => { URL.revokeObjectURL(url); downloads.delete(url); }, 1000);
      message('Relatório ' + label + ' preparado para download.');
    } catch (error) {
      if (stamp !== generation) return;
      if (error.status === 401) reset(messages[401]);
      else {
        if ([403, 404, 409].includes(error.status)) clearReport();
        message(error.code === 'export_busy' ? 'Outra exportação está em andamento. Aguarde e tente novamente.' :
          messages[error.status] || 'Não foi possível preparar o download. Tente novamente.');
      }
    } finally {
      if (stamp === generation) {
        busy = false; controls();
        if (page) el(button).focus();
        else if (token) el('assessment').focus();
      }
    }
  }
  function fail(error, stamp, login = false) {
    if (stamp !== generation) return;
    if (error.status === 401 && !login) { reset(messages[401]); return; }
    const text = login && error.status === 401 ? 'Usuário ou senha inválidos.' : messages[error.status] || 'Não foi possível concluir a solicitação. Tente novamente.';
    // A failed page must not leave stale data or an invalid continuation visible.
    if (!login) clearReport();
    message(text);
  }
  function textNode(tag, text) {
    const node = document.createElement(tag); node.textContent = text == null ? '—' : String(text); return node;
  }
  function clearAssessments(text = 'Entre para carregar a lista.') {
    grants = null;
    const placeholder = textNode('option', 'Selecione um assessment'); placeholder.value = '';
    el('assessment-selector').replaceChildren(placeholder); el('assessment-selector').value = '';
    el('assessment-list-message').textContent = text;
  }
  async function loadAssessments() {
    if (busy || !token) return;
    const stamp = generation; busy = true;
    clearAssessments('Carregando assessments permitidos…'); controls();
    try {
      const doc = await request('/api/v1/operator/assessments');
      if (stamp !== generation) return;
      const ids = doc.assessment_ids;
      if (doc.status !== 'allowed' || doc.version !== '0.6.16' || doc.source !== 'local_operator_policy' ||
          doc.assessment_existence_checked !== false || !Array.isArray(ids) || ids.length > 128 ||
          ids.some((id, index) => typeof id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id) ||
            (index > 0 && ids[index - 1] >= id))) throw new Error('invalid_assessment_directory');
      grants = ids.slice();
      const options = grants.map(id => { const option = textNode('option', id); option.value = id; return option; });
      el('assessment-selector').append(...options);
      if (grants.includes(el('assessment').value)) el('assessment-selector').value = el('assessment').value;
      el('assessment-list-message').textContent = grants.length ?
        grants.length + ' assessment(s) permitido(s). Selecione e clique em Consultar.' :
        'Sua conta não possui assessments permitidos.';
    } catch (error) {
      if (stamp !== generation) return;
      if (error.status === 401) reset(messages[401]);
      else clearAssessments('Não foi possível carregar a lista. Atualize ou informe um ID autorizado abaixo.');
    } finally {
      if (stamp === generation) { busy = false; controls(); }
    }
  }
  function detail(cell, label, data) {
    const block = document.createElement('details');
    block.append(textNode('summary', label), textNode('pre', JSON.stringify(data, null, 2)));
    cell.append(block);
  }
  const outcomes = {finding: 'finding', no_finding: 'sem finding', insufficient_evidence: 'evidência insuficiente', not_applicable: 'não aplicável', not_supported: 'não suportado'};
  function render(doc, number) {
    el('report-title').textContent = doc.assessment_id;
    el('lifecycle').textContent = doc.lifecycle.state + ' · revisão ' + doc.lifecycle.revision;
    el('asset-count').textContent = String(doc.identity.central_asset_count);
    el('evaluation-count').textContent = String(doc.coverage.evaluation_count);
    el('finding-count').textContent = String(doc.recorded_finding_occurrences);
    const c = doc.coverage;
    el('coverage').textContent = `${c.analyzed_import_count} análises / ${c.import_count} importações · ${c.credentialed_sources_evaluated} fontes avaliadas / ${c.credentialed_sources_indexed} fontes indexadas · projeção: ${c.projection_status}`;
    el('outcomes').textContent = Object.entries(outcomes).map(([key, label]) => `${label}: ${c.outcomes[key]}`).join(' · ');
    el('scope').textContent = doc.report_scope_sha256;
    el('snapshot').textContent = 'Consulta em UTC: ' + doc.snapshot_at_utc;
    const rows = doc.evaluations.map(record => {
      const row = document.createElement('tr');
      const rule = document.createElement('td');
      rule.append(textNode('strong', record.rule_id), textNode('p', record.rule.title), textNode('p', outcomes[record.result] || record.result));
      const asset = document.createElement('td');
      asset.append(textNode('strong', record.asset_id), textNode('p', record.link_state), textNode('p', record.asset_decision), textNode('p', record.asset_reason_code));
      const source = document.createElement('td');
      source.append(textNode('strong', record.source_path), textNode('p', record.bundle_id), textNode('p', record.source_sha256));
      detail(source, 'Proveniência', {analysis_id: record.analysis_id, ordinal: record.ordinal, observation_ordinal: record.observation_ordinal, evidence_refs: record.evidence_refs});
      const finding = document.createElement('td');
      finding.append(textNode('strong', record.finding_id), textNode('p', record.finding_status));
      if (record.finding_id) {
        finding.append(textNode('p', record.rule.recommendation));
        detail(finding, 'Evidência registrada', record.evidence);
      }
      row.append(rule, asset, source, finding); return row;
    });
    el('evaluations').replaceChildren(...rows);
    el('empty-page').hidden = rows.length !== 0;
    el('page-label').textContent = `Página ${number} · ${rows.length} avaliação(ões)`;
    el('report-panel').hidden = false;
    el('report-title').focus();
  }
  async function read(continuation = false) {
    if (busy || !token) return;
    const selected = continuation ? selection : {assessment: el('assessment').value.trim(), limit: el('page-size').value};
    if (!selected || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(selected.assessment)) { message(messages[400]); return; }
    const previous = continuation ? page : null;
    if (continuation && (!previous || !previous.has_more)) return;
    const number = previous ? previous.number + 1 : 1;
    const query = new URLSearchParams({limit: selected.limit});
    if (previous) {
      query.set('after_analysis_id', previous.next_cursor.after_analysis_id);
      query.set('after_ordinal', String(previous.next_cursor.after_ordinal));
      query.set('expected_scope_sha256', previous.report_scope_sha256);
    }
    const stamp = generation; busy = true; controls(); message('Consultando relatório…');
    try {
      const doc = await request('/api/v1/assessments/' + encodeURIComponent(selected.assessment) + '/report?' + query);
      if (stamp !== generation) return;
      if (doc.status !== 'found' || doc.assessment_id !== selected.assessment || doc.source_bytes_revalidated !== false ||
          !/^[0-9a-f]{64}$/.test(doc.report_scope_sha256) || (previous && doc.report_scope_sha256 !== previous.report_scope_sha256)) {
        throw Object.assign(new Error('invalid_report'), {status: previous ? 409 : 503});
      }
      render(doc, number);
      selection = selected; page = {...doc, number};
      message('Relatório carregado.');
    } catch (error) { fail(error, stamp); }
    finally { if (stamp === generation) { busy = false; controls(); } }
  }
  el('login-form').addEventListener('submit', async event => {
    event.preventDefault(); if (busy || token) return;
    const stamp = generation; let loggedIn = false; busy = true; controls(); message('Entrando…');
    const body = JSON.stringify({username: el('username').value, password: el('password').value});
    el('password').value = '';
    try {
      const doc = await request('/api/v1/operator/session', {method: 'POST', headers: {'Content-Type': 'application/json'}, body}, '');
      if (stamp !== generation) return;
      if (!/^[A-Za-z0-9_-]{43}$/.test(doc.access_token) || doc.token_type !== 'Bearer' ||
          !Number.isInteger(doc.expires_in) || doc.expires_in < 1 || doc.expires_in > 900) throw new Error('invalid_session');
      token = doc.access_token;
      expiry = setTimeout(() => reset(messages[401]), doc.expires_in * 1000);
      el('username').value = '';
      el('operator-name').textContent = doc.operator_id;
      el('login-panel').hidden = true; el('workspace').hidden = false;
      el('assessment').focus(); message('Escolha um assessment permitido ou informe seu ID.');
      loggedIn = true;
    } catch (error) { fail(error, stamp, true); }
    finally { if (stamp === generation) { busy = false; controls(); } }
    if (loggedIn && stamp === generation) await loadAssessments();
  });
  el('assessment-refresh-button').addEventListener('click', loadAssessments);
  el('assessment-selector').addEventListener('change', () => {
    if (busy || !token) return;
    const selected = el('assessment-selector').value;
    if (!selected) return;
    if (!grants || !grants.includes(selected)) { message(messages[400]); return; }
    el('assessment').value = selected;
    clearReport(); controls(); message('Assessment selecionado. Clique em Consultar.');
  });
  el('assessment').addEventListener('input', () => {
    el('assessment-selector').value = grants && grants.includes(el('assessment').value) ? el('assessment').value : '';
  });
  el('logout-button').addEventListener('click', async () => {
    const previous = token; reset('Sessão encerrada neste navegador.'); el('username').focus();
    const stamp = generation;
    if (!previous) return;
    try { await request('/api/v1/operator/session', {method: 'DELETE'}, previous); }
    catch (error) { if (stamp === generation && error.status !== 401) message('Sessão removida deste navegador. Não foi possível confirmar a revogação no servidor; ela expira em até 15 minutos.'); }
  });
  el('report-form').addEventListener('submit', event => { event.preventDefault(); read(); });
  el('next-button').addEventListener('click', () => read(true));
  el('download-button').addEventListener('click', () => download('technical'));
  el('executive-download-button').addEventListener('click', () => download('executive'));
  el('restart-button').addEventListener('click', () => {
    if (busy || !selection) return;
    el('assessment').value = selection.assessment; el('page-size').value = selection.limit; read();
  });
  window.addEventListener('pagehide', () => reset());
  window.addEventListener('pageshow', event => { if (event.persisted) reset('Entre novamente.'); });
  controls();
})();
