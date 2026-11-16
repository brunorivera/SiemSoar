'use strict';

/*
 * Single-page UI for the SIEM/SOAR thesis prototype.
 * No external dependencies: plain HTML, CSS and JavaScript.
 */

const API_BASE = window.location.protocol === 'file:' ? 'http://127.0.0.1:8000' : '';
const state = { dashboard: null, loading: false, busy: false };

const $ = (selector, root = document) => root.querySelector(selector);

const STATUS_LABEL = {
  new: 'nueva',
  investigating: 'en análisis',
  resolved: 'resuelta',
  false_positive: 'falso positivo',
};

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[ch]));
}

function fmtNum(value) {
  if (value === null || value === undefined || value === '') return '—';
  const number = Number(value);
  if (Number.isNaN(number)) return String(value);
  return new Intl.NumberFormat('es-AR').format(number);
}

function fmtTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleTimeString('es-AR', { hour12: false });
}

function fmtDateTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString('es-AR', { hour12: false });
}

function fmtDuration(totalSeconds) {
  const seconds = Math.max(0, Number(totalSeconds) || 0);
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return `${String(minutes).padStart(2, '0')}:${String(rest).padStart(2, '0')}`;
}

function sevClass(severity) {
  const value = String(severity || '').toLowerCase();
  if (['critical', 'high', 'medium', 'low'].includes(value)) return `sev-${value}`;
  return 'sev-default';
}

function statusClass(status) {
  const value = String(status || '').toLowerCase();
  return `status-${value || 'new'}`;
}

function statusLabel(status) {
  return STATUS_LABEL[String(status || '').toLowerCase()] || status || '—';
}

async function api(path, options = {}) {
  const { method = 'GET', body = null } = options;
  const response = await fetch(API_BASE + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
    cache: 'no-store',
  });
  let data = null;
  try {
    data = await response.json();
  } catch (_) {
    data = null;
  }
  if (!response.ok) {
    const detail = data && data.detail !== undefined ? data.detail : data && data.message;
    const message = typeof detail === 'string' ? detail : JSON.stringify(detail || {});
    throw new Error(message || `HTTP ${response.status}`);
  }
  return data;
}

function setConn(ok, errorMessage = '') {
  const pill = $('#conn-status');
  if (!pill) return;
  pill.classList.remove('pill-ok', 'pill-bad', 'pill-wait');
  if (ok) {
    pill.classList.add('pill-ok');
    pill.textContent = 'API conectada';
    pill.title = `${API_BASE || window.location.origin}/api/dashboard`;
  } else {
    pill.classList.add('pill-bad');
    pill.textContent = 'API sin conexión';
    pill.title = errorMessage || `No se pudo alcanzar ${API_BASE}/api/dashboard`;
  }
}

function logAction(message, kind = 'info') {
  const box = $('#action-log');
  if (!box) return;
  box.className = `action-log ${kind}`;
  const time = new Date().toLocaleTimeString('es-AR', { hour12: false });
  box.innerHTML = `<span class="log-time">${escapeHtml(time)}</span> ${escapeHtml(message)}`;
}

function applyBusyState() {
  document.querySelectorAll('button.btn').forEach((button) => {
    button.disabled = state.busy;
  });
}

function setBusy(value) {
  state.busy = Boolean(value);
  applyBusyState();
}

function sourceIp() {
  const input = $('#source-ip');
  return input ? input.value.trim() : '';
}

function metricCard(label, value, sub) {
  return `
    <div class="metric-card">
      <div class="metric-label" title="${escapeHtml(label)}">${escapeHtml(label)}</div>
      <div class="metric-value">${escapeHtml(String(value))}</div>
      <div class="metric-sub">${escapeHtml(sub || '')}</div>
    </div>`;
}

function renderDashboard(data) {
  state.dashboard = data;
  const metrics = data.metrics || {};
  const alerts = data.alerts || [];
  const blocks = data.blocked_ips || [];
  const runs = data.pipeline_runs || [];
  const rules = data.rules || [];

  const mttd = metrics.mttd_seconds === null || metrics.mttd_seconds === undefined
    ? '—'
    : `${metrics.mttd_seconds} s`;

  $('#metrics-grid').innerHTML = [
    metricCard('Eventos parseados', fmtNum(metrics.events_parsed_total), 'parsed_events'),
    metricCard('Alertas generadas', fmtNum(metrics.alerts_total), 'alerts'),
    metricCard('Ciclos ejecutados', fmtNum(metrics.pipeline_runs_total), 'pipeline_runs'),
    metricCard('IPs bloqueadas', fmtNum(metrics.blocked_active), 'TTL activo'),
    metricCard('MTTD estimado', mttd, `${fmtNum(metrics.mttd_samples)} muestra(s)`),
    metricCard('Líneas recibidas', fmtNum(metrics.lines_received_total), 'ingesta acumulada'),
  ].join('');

  $('#last-run').textContent = metrics.last_run_at
    ? `Último ciclo: ${fmtTime(metrics.last_run_at)}`
    : 'Último ciclo: —';
  $('#grace-chip').textContent = `${fmtNum(metrics.grace_seconds)} s`;
  $('#ttl-chip').textContent = `${fmtNum(metrics.block_ttl_seconds)} s`;
  $('#alerts-count').textContent = `${fmtNum(metrics.alerts_total)} alerta(s)`;

  renderRules(rules);
  renderRuns(runs);
  renderAlerts(alerts);
  renderBlocks(blocks);
  updateCountdowns();
  applyBusyState();
}

function renderRules(rules) {
  const container = $('#rules-list');
  if (!container) return;
  if (!rules.length) {
    container.innerHTML = '<div class="rule-item"><span class="rule-desc">Sin reglas activas.</span></div>';
    return;
  }
  container.innerHTML = rules.map((rule) => `
    <div class="rule-item">
      <span class="rule-name" title="${escapeHtml(rule.description || '')}">${escapeHtml(rule.name)}</span>
      <span class="rule-meta">${escapeHtml(rule.threshold)}/${escapeHtml(rule.time_window)} s</span>
      <span class="sev-badge ${sevClass(rule.severity)}">${escapeHtml(rule.severity)}</span>
      <span class="rule-desc">${escapeHtml(rule.pattern)}</span>
    </div>`).join('');
}

function renderRuns(runs) {
  const tbody = $('#runs-table tbody');
  if (!tbody) return;
  if (!runs.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="8">Todavía no se ejecutó ningún ciclo.</td></tr>';
    return;
  }
  tbody.innerHTML = runs.map((run) => `
    <tr>
      <td class="mono">${escapeHtml(run.id)}</td>
      <td class="mono nowrap" title="${escapeHtml(fmtDateTime(run.run_ts))}">${escapeHtml(fmtTime(run.run_ts))}</td>
      <td class="mono" title="${escapeHtml(run.notes || '')}">${escapeHtml(run.trigger)}</td>
      <td class="mono">${fmtNum(run.lines_read)}</td>
      <td class="mono">${fmtNum(run.events_parsed)}</td>
      <td class="mono">${fmtNum(run.alerts_created)}</td>
      <td class="mono">${fmtNum(run.duration_ms)}</td>
      <td><span class="status-badge ${run.status === 'ok' ? 'status-resolved' : 'status-new'}">${escapeHtml(run.status)}</span></td>
    </tr>`).join('');
}

function renderAlerts(alerts) {
  const tbody = $('#alerts-table tbody');
  if (!tbody) return;
  if (!alerts.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="6">Sin alertas todavía. Ejecuta una simulación de ataque.</td></tr>';
    return;
  }
  tbody.innerHTML = alerts.map((alert) => `
    <tr>
      <td class="mono nowrap" title="${escapeHtml(fmtDateTime(alert.timestamp))}">${escapeHtml(fmtTime(alert.timestamp))}</td>
      <td class="ip">${escapeHtml(alert.source_ip || '—')}</td>
      <td class="rule-cell">
        <span class="alert-rule">${escapeHtml(alert.rule_name || '—')}</span>
        <span class="alert-desc" title="${escapeHtml(alert.description || '')}">${escapeHtml(alert.description || '')}</span>
      </td>
      <td><span class="sev-badge ${sevClass(alert.severity)}">${escapeHtml(alert.severity)}</span></td>
      <td class="mono">${fmtNum(alert.event_count)}</td>
      <td><span class="status-badge ${statusClass(alert.status)}">${escapeHtml(statusLabel(alert.status))}</span></td>
    </tr>`).join('');
}

function renderBlocks(blocks) {
  const tbody = $('#blocks-table tbody');
  if (!tbody) return;
  if (!blocks.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="6">Sin bloqueos activos. Una simulación de ataque debería crear uno.</td></tr>';
    return;
  }
  tbody.innerHTML = blocks.map((block) => `
    <tr>
      <td class="ip">${escapeHtml(block.ip)}</td>
      <td class="rule-cell">
        <span class="alert-rule">${escapeHtml(block.rule_name || '—')}</span>
        <span class="alert-desc" title="${escapeHtml(block.reason || '')}">${escapeHtml(block.reason || '')}</span>
      </td>
      <td class="mono nowrap" title="${escapeHtml(fmtDateTime(block.blocked_at))}">${escapeHtml(fmtTime(block.blocked_at))}</td>
      <td class="mono nowrap" title="${escapeHtml(fmtDateTime(block.expires_at))}">${escapeHtml(fmtTime(block.expires_at))}</td>
      <td class="ttl-cell" data-expires="${escapeHtml(block.expires_at)}">${escapeHtml(fmtDuration(block.ttl_remaining))}</td>
      <td><button class="btn btn-unblock" type="button" data-unblock="${escapeHtml(block.ip)}">Desbloquear</button></td>
    </tr>`).join('');
}

function updateCountdowns() {
  document.querySelectorAll('[data-expires]').forEach((cell) => {
    const expires = cell.getAttribute('data-expires');
    const target = new Date(expires).getTime();
    if (Number.isNaN(target)) {
      cell.textContent = '—';
      return;
    }
    const remaining = Math.max(0, Math.floor((target - Date.now()) / 1000));
    cell.textContent = remaining > 0 ? fmtDuration(remaining) : 'expirado';
    cell.classList.toggle('expired', remaining <= 0);
  });
}

async function refresh(silent = false) {
  if (state.loading) return;
  state.loading = true;
  try {
    const data = await api('/api/dashboard');
    renderDashboard(data);
    setConn(true);
  } catch (error) {
    setConn(false, error.message);
    if (!silent) logAction(`No se pudo consultar /api/dashboard: ${error.message}`, 'error');
  } finally {
    state.loading = false;
  }
}

async function runIngest(payload, label) {
  setBusy(true);
  try {
    const response = await api('/api/ingest', { method: 'POST', body: payload });
    const ingest = response.ingest || {};
    const cycle = response.cycle;
    const parts = [
      `${label}: ${fmtNum(ingest.lines_received || 0)} línea(s) → ${fmtNum(ingest.events_inserted || 0)} evento(s) parseado(s).`,
    ];
    if (response.meta && response.meta.source_ip) parts.push(`IP ${response.meta.source_ip}.`);
    if (response.meta && response.meta.note) parts.push(response.meta.note);
    if (cycle) {
      const blocked = cycle.blocked || [];
      const excluded = cycle.excluded_skipped || [];
      parts.push(
        `Ciclo #${cycle.run_id}: ${fmtNum(cycle.alerts_created)} alerta(s), ` +
        `${fmtNum(blocked.length)} bloqueo(s), ${fmtNum(excluded.length)} exclusión(es), ` +
        `${fmtNum(cycle.dedup_skipped)} duplicado(s).`
      );
      if (blocked.length) {
        parts.push(`Bloqueadas: ${blocked.map((item) => item.ip).join(', ')} (TTL ${blocked[0].ttl_seconds} s).`);
      }
      if (excluded.length) {
        parts.push(`R5 omitió: ${[...new Set(excluded.map((item) => item.ip))].join(', ')}.`);
      }
    }
    logAction(parts.join(' '), cycle && cycle.alerts_created > 0 ? 'success' : 'info');
    await refresh(true);
  } catch (error) {
    logAction(`Error en la simulación: ${error.message}`, 'error');
  } finally {
    setBusy(false);
  }
}

async function submitCustomLines() {
  const textarea = $('#custom-lines');
  const lines = (textarea ? textarea.value : '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (!lines.length) {
    logAction('Pega al menos una línea de log para ingestarla.', 'warn');
    return;
  }
  await runIngest(
    { scenario: 'custom', events: lines, run_cycle: true },
    `Ingesta manual (${lines.length} línea(s))`
  );
}

async function handleUnblock(ip) {
  setBusy(true);
  try {
    const response = await api('/api/unblock', { method: 'POST', body: { ip } });
    logAction(response.message || `IP ${ip} desbloqueada.`, response.ok ? 'success' : 'warn');
    await refresh(true);
  } catch (error) {
    logAction(`Error al desbloquear ${ip}: ${error.message}`, 'error');
  } finally {
    setBusy(false);
  }
}

async function handleCycle() {
  setBusy(true);
  try {
    const response = await api('/api/run-cycle', { method: 'POST', body: { trigger: 'manual' } });
    const cycle = response.cycle || {};
    const blocked = cycle.blocked || [];
    const excluded = cycle.excluded_skipped || [];
    logAction(
      `Ciclo #${cycle.run_id}: ${fmtNum(cycle.lines_read)} línea(s), ` +
      `${fmtNum(cycle.events_parsed)} evento(s), ${fmtNum(cycle.alerts_created)} alerta(s), ` +
      `${fmtNum(blocked.length)} bloqueo(s), ${fmtNum(excluded.length)} exclusión(es), ` +
      `${fmtNum(cycle.dedup_skipped)} duplicado(s).`,
      cycle.alerts_created > 0 ? 'success' : 'info'
    );
    await refresh(true);
  } catch (error) {
    logAction(`Error al ejecutar el ciclo: ${error.message}`, 'error');
  } finally {
    setBusy(false);
  }
}

async function handleReset() {
  if (!window.confirm('¿Reiniciar la demo? Se borran eventos, alertas, ciclos y bloqueos; las 5 reglas se conservan.')) {
    return;
  }
  setBusy(true);
  try {
    const response = await api('/api/reset', { method: 'POST' });
    logAction(response.message || 'Datos de demostración reiniciados.', 'success');
    await refresh(true);
  } catch (error) {
    logAction(`Error al reiniciar la demo: ${error.message}`, 'error');
  } finally {
    setBusy(false);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.addEventListener('click', (event) => {
    const scenarioButton = event.target.closest('[data-scenario]');
    if (scenarioButton) {
      if (state.busy) return;
      const scenario = scenarioButton.dataset.scenario;
      const fixedIp = scenarioButton.dataset.fixedIp;
      const payload = { scenario, run_cycle: true };
      const ip = fixedIp || sourceIp();
      if (ip) payload.source_ip = ip;
      const labelNode = scenarioButton.querySelector('span');
      const label = fixedIp
        ? `Exclusión R5 (${fixedIp})`
        : (labelNode ? labelNode.textContent : scenario);
      runIngest(payload, label);
      return;
    }

    const unblockButton = event.target.closest('[data-unblock]');
    if (unblockButton) {
      if (state.busy) return;
      handleUnblock(unblockButton.dataset.unblock);
    }
  });

  const cycleButton = $('#cycle-btn');
  if (cycleButton) cycleButton.addEventListener('click', handleCycle);

  const customButton = $('#custom-btn');
  if (customButton) customButton.addEventListener('click', submitCustomLines);

  const textarea = $('#custom-lines');
  if (textarea) {
    textarea.addEventListener('keydown', (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
        event.preventDefault();
        submitCustomLines();
      }
    });
  }

  const resetButton = $('#reset-btn');
  if (resetButton) resetButton.addEventListener('click', handleReset);

  refresh();
  setInterval(() => refresh(true), 2500);
  setInterval(updateCountdowns, 1000);
});
