// Single-file web UI logic. Vanilla JS — no build step.

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);
const api = async (path, opts={}) => {
  const r = await fetch(path, {headers:{'content-type':'application/json'}, ...opts});
  if (!r.ok) throw new Error(`${path} → ${r.status} ${await r.text()}`);
  return r.json();
};

// --- Tab switching ---
$$('.tab').forEach(t => t.addEventListener('click', () => switchTab(t.dataset.tab)));
$$('[data-jump]').forEach(a => a.addEventListener('click', (e) => {
  e.preventDefault(); switchTab(a.dataset.jump);
}));
function switchTab(name) {
  $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  $$('.panel').forEach(p => p.classList.toggle('active', p.id === `tab-${name}`));
  if (name === 'sessions') loadSessions();
  if (name === 'protocol') loadProtocolEntries();
  if (name === 'dongle') { loadDongleInfo(); loadLTKs(); }
  if (name === 'integrations') loadIntegrations();
  if (name === 'capture') { reconcileCaptureState(); loadAliases(); detectPklgFile(/*silent*/true); }
}

async function detectPklgFile(silent = false) {
  try {
    const r = await fetch('/api/pklg/detect');
    const j = await r.json();
    if (j.path) {
      const input = $('#pklg-tail-path-input');
      if (input && !input.value) input.value = j.path;
      $('#pklg-detect-status').innerHTML =
        `✓ PL is writing to <code>${j.path}</code> (${(j.size/1024).toFixed(1)} KB)`;
    } else if (!silent) {
      $('#pklg-detect-status').textContent = j.reason || 'No live PL file found.';
    }
  } catch (e) {
    if (!silent) $('#pklg-detect-status').textContent = 'detect failed: ' + e.message;
  }
}

$('#btn-detect-pklg')?.addEventListener('click', () => detectPklgFile(false));

// Poll capture status every 2s and surface late-arriving daemon errors
// (e.g., pklg_tail file timeout, source crash).
let captureWatchTimer = null;
function startCaptureWatcher() {
  if (captureWatchTimer) return;
  captureWatchTimer = setInterval(async () => {
    try {
      const h = await api('/api/health');
      const s = h.capture_status;
      if (!s) return;
      if (s.error) {
        $('#capture-active').classList.add('hidden');
        $('#capture-error').classList.remove('hidden');
        $('#capture-error-msg').textContent = s.error;
        $('#capture-error-hint').textContent = "Capture failed after start. Common causes: " +
          "wrong PL file path; PL stopped recording; Bluetooth Debug Profile not installed.";
        stopCaptureWatcher();
        stopWS();
      } else if (!h.capture_running) {
        // Capture ended cleanly — refresh sessions list
        stopCaptureWatcher();
      } else if (s.session_id != null) {
        // Mirror server state to UI (in case sources update packet_count out of band)
        $('#capture-count').textContent = s.packet_count ?? '0';
        if (s.device_filter && s.device_filter.length) {
          $('#capture-filter-stats').classList.remove('hidden');
          $('#capture-seen').textContent = s.packets_seen ?? '0';
          $('#capture-dropped').textContent = s.packets_dropped_by_filter ?? '0';
        }
      }
    } catch (_) { /* keep polling */ }
  }, 2000);
}
function stopCaptureWatcher() {
  if (captureWatchTimer) { clearInterval(captureWatchTimer); captureWatchTimer = null; }
}

// If a capture is already running on the server (e.g. browser was refreshed mid-capture,
// or a previous start hung), show the active-capture pane with the existing session_id.
async function reconcileCaptureState() {
  try {
    const h = await api('/api/health');
    if (h.capture_running && h.capture_status?.session_id) {
      const s = h.capture_status;
      $('#capture-active').classList.remove('hidden');
      $('#capture-label').textContent = (s.label || '(unknown)') + ' [running]';
      $('#capture-sid').textContent = s.session_id;
      $('#capture-count').textContent = s.packet_count ?? '0';
      $('#capture-no-packets-hint').classList.toggle('hidden', (s.packet_count ?? 0) > 0);
      // Open WS so we see new packets as they arrive
      startWS();
    } else {
      // No capture running — make sure stale UI state is cleared
      $('#capture-active').classList.add('hidden');
    }
  } catch (_) { /* ignore */ }
}

// --- Health badge ---
async function loadHealth() {
  try {
    const h = await api('/api/health');
    const el = $('#health');
    if (h.capture_running) {
      el.textContent = `capturing — ${h.sessions_total} sessions`;
      el.className = 'status ok';
    } else {
      el.textContent = `idle — dongle ${h.dongle_port ?? 'not detected'} — ${h.sessions_total} sessions`;
      el.className = h.dongle_port ? 'status ok' : 'status';
    }
    return h;
  } catch (e) {
    $('#health').textContent = 'offline';
    $('#health').className = 'status bad';
  }
}
setInterval(loadHealth, 4000);
loadHealth();

// --- Capture ---
// Capture status tracking
let captureNoPacketsTimer = null;
let lastPacketAt = 0;
let recentPacketTimestamps = [];

// Show/hide the PL tail path field based on source
function syncCaptureSourceUI() {
  const src = $('#capture-source-select').value;
  $('#capture-pklg-path-row').style.display = (src === 'pklg_tail') ? '' : 'none';
}
$('#capture-source-select')?.addEventListener('change', syncCaptureSourceUI);
syncCaptureSourceUI();

$('#capture-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = Object.fromEntries(fd);
  // Promote pklg_tail_path → source_args
  if (payload.source === 'pklg_tail') {
    if (!payload.pklg_tail_path) {
      $('#capture-error').classList.remove('hidden');
      $('#capture-error-msg').textContent = 'pklg_tail source needs a save-file path.';
      $('#capture-error-hint').textContent = 'In PL.app: hit record, File → Save Live Capture As… → put the same path here.';
      return;
    }
    payload.source_args = { path: payload.pklg_tail_path };
  }
  delete payload.pklg_tail_path;
  // Promote device_filter (CSV) → list
  if (payload.device_filter) {
    payload.device_filter = payload.device_filter.split(',').map(s => s.trim()).filter(Boolean);
    if (!payload.device_filter.length) delete payload.device_filter;
  } else {
    delete payload.device_filter;
  }
  const body = JSON.stringify(payload);
  $('#capture-error').classList.add('hidden');
  $('#capture-active').classList.add('hidden');
  try {
    const r = await fetch('/api/sessions', {method:'POST', headers:{'content-type':'application/json'}, body});
    const json = await r.json();
    if (!r.ok) throw new Error(json.detail || json.message || JSON.stringify(json));
    $('#capture-active').classList.remove('hidden');
    const filterStr = json.device_filter && json.device_filter.length
      ? ` 🎯 ${json.device_filter.length} device${json.device_filter.length > 1 ? 's' : ''}` : '';
    $('#capture-label').textContent = fd.get('label') + ' [' + fd.get('source') + ']' + filterStr;
    $('#capture-sid').textContent = json.session_id;
    $('#capture-filter-stats').classList.toggle('hidden', !(json.device_filter && json.device_filter.length));
    // UUID-vs-MAC sanity check: warn if filtering pklg_tail by only UUIDs.
    if (payload.source === 'pklg_tail' && json.device_filter && json.device_filter.length) {
      const isUUID = a => /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(a);
      const isMAC = a => /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(a);
      const onlyUUIDs = json.device_filter.every(isUUID);
      const noMACs = !json.device_filter.some(isMAC);
      if (onlyUUIDs && noMACs) {
        const hint = document.createElement('div');
        hint.className = 'big-pill';
        hint.style.cssText = 'background: var(--warn); color: #0b0c10; margin-top: 8px;';
        hint.innerHTML = `⚠️ Filter contains only CoreBluetooth UUIDs. PL captures real MACs, so 0 packets will match.<br>
          <strong>Fix:</strong> run a Probe on the device (with this capture running) to auto-bridge UUID→MAC, then re-start with the filter.`;
        $('#capture-active').appendChild(hint);
      }
    }
    $('#capture-count').textContent = '0';
    $('#capture-rate').textContent = '0';
    $('#capture-last-seen').textContent = 'no packets yet';
    $('#capture-no-packets-hint').classList.add('hidden');
    $('#live-packets tbody').innerHTML = '';
    $('#marker-list').innerHTML = '';
    $('#live-filter-chips').innerHTML = '';
    liveFilterChips.clear();
    liveDeviceCounts.clear();
    liveDeviceNames.clear();
    $('#live-devices').innerHTML = '';
    delete $('#live-devices').dataset.size;
    lastPacketAt = 0;
    recentPacketTimestamps = [];
    clearTimeout(captureNoPacketsTimer);
    captureNoPacketsTimer = setTimeout(() => {
      if (recentPacketTimestamps.length === 0) {
        $('#capture-no-packets-hint').classList.remove('hidden');
      }
    }, 4000);
    startWS();
    startCaptureWatcher();
    loadHealth();
  } catch (err) {
    $('#capture-error').classList.remove('hidden');
    $('#capture-error-msg').textContent = err.message;
    const src = fd.get('source');
    let hint = '';
    const isConflict = /409|already running/i.test(err.message);
    if (isConflict) {
      hint = "A capture is already running (probably stuck). Click 'Force stop existing' to terminate it, then click Start again.";
      // Inject a force-stop button
      const btn = document.createElement('button');
      btn.type = 'button'; btn.textContent = 'Force stop existing';
      btn.style.marginTop = '8px';
      btn.addEventListener('click', async () => {
        const h = await api('/api/health');
        const sid = h?.capture_status?.session_id;
        if (sid) await fetch(`/api/sessions/${sid}/stop`, {method:'POST'}).catch(()=>{});
        $('#capture-error').classList.add('hidden');
        reconcileCaptureState();
      });
      // Replace any previous force-stop button before re-adding
      $$('#capture-error button').forEach(b => b.remove());
      $('#capture-error').appendChild(btn);
    } else if (src === 'pklg_tail') {
      hint = "Make sure PL.app is recording AND File → Save Live Capture As… points at the same path you entered. " +
             "Also confirm Apple's Bluetooth Logging profile is installed (so PL captures real packets).";
    } else if (src === 'nrf_sniffer') {
      hint = "nRF source needs the dongle plugged in with sniffer firmware. " +
             "Run `bt-spy doctor` in a terminal, or flash via the Dongle tab.";
    }
    hint += " (Tip: try the Probe form below — its 'Record as' field is now auto-filled and works without any capture source.)";
    $('#capture-error-hint').textContent = hint;
  }
});

// Scan / probe
$('#scan-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const tbody = $('#scan-results tbody');
  tbody.innerHTML = '<tr><td colspan=5><em>scanning…</em></td></tr>';
  const r = await fetch('/api/ble/scan?duration=' + fd.get('duration'));
  const results = await r.json();
  tbody.innerHTML = results.map(d =>
    `<tr><td><code>${d.address}</code></td><td>${d.name ?? ''}</td><td>${d.rssi ?? ''}</td>
     <td>${(d.service_uuids||[]).slice(0,3).join('<br>')}</td>
     <td><button class="pick-probe" data-addr="${d.address}">Probe</button></td></tr>`
  ).join('') || '<tr><td colspan=5><em>No devices.</em></td></tr>';
  $$('.pick-probe').forEach(b => b.addEventListener('click', () => {
    $('#probe-form [name=address]').value = b.dataset.addr;
  }));
});
$('#probe-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const data = Object.fromEntries(fd);
  data.listen_for_notifications_ms = +data.listen_for_notifications_ms;
  if (data.record_as && data.record_as.trim()) {
    // Suffix with timestamp so repeated probes don't all share one label.
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    data.record_as = `${data.record_as.trim()}_${ts}`;
  } else {
    delete data.record_as;
  }
  if (data.record_as) startWS();  // open WS so live feed shows the probe's packets
  $('#probe-result').textContent = 'connecting + enumerating…';
  try {
    const r = await fetch('/api/ble/probe', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(data)});
    const json = await r.json();
    let header = '';
    if (json.session_id) {
      header = `✓ recorded as session #${json.session_id} (${json.characteristics.length} characteristics)\n`;
      if (json.error) header += `(probe error: ${json.error})\n`;
    } else if (json.error) {
      header = `✗ probe error: ${json.error}\n`;
    }
    if (json.bridged_aliases && json.bridged_aliases.length) {
      for (const b of json.bridged_aliases) {
        if (b.mac) {
          header += `🔗 bridged: ${b.mac} → "${b.name}" (from ${b.from_address})\n`;
        } else if (b.ambiguous_macs) {
          header += `🔗 multiple MACs seen during probe — skipped auto-naming:\n   ${b.ambiguous_macs.join(', ')}\n`;
        }
      }
    }
    header += `\n`;
    $('#probe-result').textContent = header + JSON.stringify(json, null, 2);
  } catch (err) {
    $('#probe-result').textContent = 'request failed: ' + err.message;
  }
  loadHealth();
  loadAliases();
});

// .pklg upload form — multipart, not JSON, so we don't go through api()
$('#import-pklg-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  $('#import-result').textContent = 'uploading…';
  const r = await fetch('/api/import_pklg', {method:'POST', body: fd});
  const json = await r.json();
  if (!r.ok) {
    $('#import-result').textContent = 'error: ' + JSON.stringify(json, null, 2);
    return;
  }
  $('#import-result').textContent = `✓ session ${json.session_id} — ${json.packet_count} packets\nuploaded to ${json.uploaded_to}`;
  loadHealth();
});
$('#btn-stop-capture').addEventListener('click', async () => {
  const sid = $('#capture-sid').textContent;
  try { await api(`/api/sessions/${sid}/stop`, {method:'POST'}); } catch (e) { /* daemon may have errored */ }
  $('#capture-active').classList.add('hidden');
  clearTimeout(captureNoPacketsTimer);
  stopCaptureWatcher();
  stopWS();
  loadHealth();
  loadSessions();
});

// ---- Live feed + filter + detail + markers ----

let ws = null;
let liveFilterText = '';
const liveFilterChips = new Set();  // values like 'conn:64' / 'dir:host->controller' / 'pdu:ATT_WRITE_REQ'

function packetMatchesFilter(pkt) {
  for (const chip of liveFilterChips) {
    const idx = chip.indexOf(':');
    const k = chip.slice(0, idx);
    const v = chip.slice(idx + 1);
    if (k === 'conn' && String(pkt.conn_handle) !== v) return false;
    if (k === 'dir' && pkt.direction !== v) return false;
    if (k === 'pdu' && pkt.pdu_type !== v) return false;
    if (k === 'dev' && pkt.device_addr !== v) return false;
  }
  if (liveFilterText) {
    const haystack = [
      pkt.ts, pkt.device_addr, pkt.conn_handle, pkt.direction, pkt.pdu_type,
      pkt.handle, pkt.payload_hex, pkt.raw_hex, (pkt.layers || []).join(','),
    ].filter(v => v != null).join(' ').toLowerCase();
    if (!haystack.includes(liveFilterText.toLowerCase())) return false;
  }
  return true;
}

// Per-device counters during live capture, rendered above the live feed.
const liveDeviceCounts = new Map();  // addr → count
const liveDeviceNames = new Map();   // addr → name (from WS events)

function bumpDevice(addr, name) {
  if (!addr) return;
  liveDeviceCounts.set(addr, (liveDeviceCounts.get(addr) || 0) + 1);
  if (name) liveDeviceNames.set(addr, name);
  renderDevicePanel();
}
function deviceLabel(addr) {
  const n = liveDeviceNames.get(addr);
  return n ? `${n} (${addr})` : addr;
}
function renderDevicePanel() {
  const panel = $('#live-devices');
  const entries = [...liveDeviceCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 60);
  if (panel.dataset.size === String(entries.length) && entries.length > 30) return;
  panel.dataset.size = String(entries.length);
  panel.innerHTML = '';
  for (const [addr, n] of entries) {
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'chip';
    b.textContent = `${deviceLabel(addr)} · ${n}`;
    b.dataset.value = `dev:${addr}`;
    if (liveFilterChips.has(`dev:${addr}`)) b.classList.add('active');
    b.addEventListener('click', (e) => {
      if (e.shiftKey) { renameAddr(addr); }
      else { toggleDeviceFilter(addr, b); }
    });
    panel.appendChild(b);
  }
}

async function renameAddr(addr) {
  const current = liveDeviceNames.get(addr) || '';
  const name = prompt(`Name for ${addr}? (blank = remove)`, current);
  if (name === null) return;
  await fetch('/api/device_alias', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({device_addr: addr, name, source: 'user'}),
  });
  if (name.trim()) liveDeviceNames.set(addr, name.trim());
  else liveDeviceNames.delete(addr);
  delete $('#live-devices').dataset.size;
  renderDevicePanel();
  loadAliases();
}

async function loadAliases() {
  try {
    const r = await fetch('/api/device_aliases');
    const aliases = await r.json();
    $('#alias-list').innerHTML = aliases.length
      ? aliases.map(a =>
          `<span class="chip" title="source: ${a.source}">
            <strong>${a.name}</strong> · <code style="font-size:10px">${a.device_addr}</code>
          </span>`).join('')
      : '<em class="hint">No aliases yet. Shift-click a device chip above to add one.</em>';
    // Populate the capture-form filter picker too
    const picker = $('#device-filter-picker');
    if (picker) {
      picker.innerHTML = '<option value="">+ add from aliases…</option>' +
        aliases.map(a =>
          `<option value="${a.device_addr}">${a.name} (${a.device_addr})</option>`
        ).join('');
    }
  } catch (_) {}
}

$('#device-filter-picker')?.addEventListener('change', (e) => {
  const v = e.target.value;
  if (!v) return;
  const input = $('#device-filter-input');
  const cur = (input.value || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!cur.includes(v)) cur.push(v);
  input.value = cur.join(', ');
  e.target.value = '';  // reset picker
});
function toggleDeviceFilter(addr, btn) {
  const v = `dev:${addr}`;
  if (liveFilterChips.has(v)) { liveFilterChips.delete(v); btn?.classList.remove('active'); }
  else { liveFilterChips.add(v); btn?.classList.add('active'); }
  reapplyLiveFilter();
}

function refreshChips(pkt) {
  const span = $('#live-filter-chips');
  const seen = new Set(Array.from(span.children).map(c => c.dataset.value));
  const candidates = [
    pkt.conn_handle != null ? `conn:${pkt.conn_handle}` : null,
    pkt.direction ? `dir:${pkt.direction}` : null,
    pkt.pdu_type ? `pdu:${pkt.pdu_type}` : null,
  ].filter(Boolean);
  for (const v of candidates) {
    if (seen.has(v)) continue;
    seen.add(v);
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'chip'; b.dataset.value = v;
    b.textContent = v;
    b.addEventListener('click', () => {
      if (liveFilterChips.has(v)) { liveFilterChips.delete(v); b.classList.remove('active'); }
      else { liveFilterChips.add(v); b.classList.add('active'); }
      reapplyLiveFilter();
    });
    span.appendChild(b);
  }
}

function reapplyLiveFilter() {
  for (const tr of $$('#live-packets tbody tr')) {
    const pkt = tr._pkt;
    if (!pkt) continue;
    tr.style.display = packetMatchesFilter(pkt) ? '' : 'none';
  }
}

$('#live-filter-text').addEventListener('input', (e) => {
  liveFilterText = e.target.value;
  reapplyLiveFilter();
});
$('#live-filter-clear').addEventListener('click', () => {
  liveFilterText = '';
  liveFilterChips.clear();
  $('#live-filter-text').value = '';
  for (const c of $$('#live-filter-chips .chip')) c.classList.remove('active');
  reapplyLiveFilter();
});

function appendLivePacket(pkt) {
  bumpDevice(pkt.device_addr, pkt.device_name);
  const tbody = $('#live-packets tbody');
  const tr = document.createElement('tr');
  tr._pkt = pkt;
  tr.dataset.packetId = pkt.packet_id;
  const devCell = pkt.device_addr
    ? (pkt.device_name
        ? `<strong>${pkt.device_name}</strong><br><code style="font-size:10px; color:var(--muted)">${pkt.device_addr}</code>`
        : `<code style="font-size:11px">${pkt.device_addr}</code>`)
    : '';
  tr.innerHTML = `<td>${pkt.ts?.toFixed(3) ?? ''}</td>
    <td>${devCell}</td>
    <td>${pkt.conn_handle ?? ''}</td>
    <td>${pkt.direction ?? ''}</td>
    <td>${pkt.pdu_type ?? ''}</td>
    <td>${pkt.handle ?? ''}</td>
    <td><code>${pkt.payload_hex ?? ''}</code></td>`;
  tr.addEventListener('click', () => openPacketDetail(pkt.packet_id));
  if (!packetMatchesFilter(pkt)) tr.style.display = 'none';
  tbody.prepend(tr);
  while (tbody.children.length > 300) tbody.removeChild(tbody.lastChild);
  refreshChips(pkt);
}

function appendMarkerRow(marker) {
  const tbody = $('#live-packets tbody');
  const tr = document.createElement('tr');
  tr.className = 'marker';
  tr.innerHTML = `<td colspan=7>▶ <strong>${marker.label}</strong>
    — covers packets ${marker.packet_id_start}..${marker.packet_id_end}
    ${marker.notes ? ' (' + marker.notes + ')' : ''}</td>`;
  tbody.prepend(tr);
}

function startWS() {
  if (ws && ws.readyState <= 1) return;
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws/packets`);
  ws.onmessage = (ev) => {
    const pkt = JSON.parse(ev.data);
    const now = Date.now();
    lastPacketAt = now;
    recentPacketTimestamps.push(now);
    while (recentPacketTimestamps.length && recentPacketTimestamps[0] < now - 5000) {
      recentPacketTimestamps.shift();
    }
    if ($('#capture-count')) {
      $('#capture-count').textContent = (parseInt($('#capture-count').textContent || '0') + 1).toString();
      $('#capture-rate').textContent = (recentPacketTimestamps.length / 5).toFixed(1);
      $('#capture-last-seen').textContent = 'last: just now';
      $('#capture-no-packets-hint').classList.add('hidden');
    }
    appendLivePacket(pkt);
  };
}
function stopWS() { ws?.close(); ws = null; }

// ---- Mark-now ----
$('#marker-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const sid = parseInt($('#capture-sid').textContent || '0');
  if (!sid) { alert('Start a capture first.'); return; }
  const body = JSON.stringify({
    session_id: sid,
    label: fd.get('label'),
    notes: fd.get('notes') || null,
  });
  const r = await fetch('/api/marker', {method:'POST', headers:{'content-type':'application/json'}, body});
  const json = await r.json();
  if (!r.ok) { alert('Marker failed: ' + JSON.stringify(json)); return; }
  appendMarkerRow(json);
  e.target.reset();
  // Append a small inline summary
  const m = document.createElement('span');
  m.className = 'marker-row';
  m.textContent = `▶ ${json.label} (${json.packet_id_start}..${json.packet_id_end})`;
  $('#marker-list').appendChild(m);
});

// ---- Packet detail modal ----
let activePacketId = null;

async function openPacketDetail(pid) {
  activePacketId = pid;
  const r = await fetch(`/api/packets/${pid}`);
  if (!r.ok) { alert('Could not load packet ' + pid); return; }
  const p = await r.json();
  $('#modal-meta').innerHTML = `
    <span>id</span><span>${p.id}</span>
    <span>session</span><span>${p.session_id}</span>
    <span>ts</span><span>${(p.ts ?? 0).toFixed(3)}s</span>
    <span>direction</span><span>${p.direction ?? '—'}</span>
    <span>pdu</span><span>${p.pdu_type ?? '—'}</span>
    <span>att handle</span><span>${p.handle != null ? '0x' + p.handle.toString(16) : '—'}</span>
    <span>conn handle</span><span>${p.conn_handle != null ? '0x' + p.conn_handle.toString(16) : '—'}</span>
    <span>opcode</span><span>${p.opcode != null ? '0x' + p.opcode.toString(16) : '—'}</span>
    <span>payload</span><span><code>${p.payload_hex ?? '—'}</code></span>
  `;
  $('#modal-raw').textContent = p.raw_hex || '—';
  $('#modal-decoded').textContent = JSON.stringify(p.decoded, null, 2);
  $('#modal-annotate-result').textContent = '';
  $('#packet-modal').classList.remove('hidden');
}
$('#modal-close').addEventListener('click', () => $('#packet-modal').classList.add('hidden'));
$('#packet-modal').addEventListener('click', (e) => {
  if (e.target.id === 'packet-modal') $('#packet-modal').classList.add('hidden');
});
$('#modal-diff-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!activePacketId) return;
  const otherId = +new FormData(e.target).get('other_id');
  if (!otherId) return;
  try {
    const [me, other] = await Promise.all([
      fetch(`/api/packets/${activePacketId}`).then(r => r.json()),
      fetch(`/api/packets/${otherId}`).then(r => r.json()),
    ]);
    $('#modal-diff-result').innerHTML = renderByteDiff(me, other);
  } catch (err) {
    $('#modal-diff-result').textContent = 'diff failed: ' + err.message;
  }
});

function renderByteDiff(a, b) {
  // Compare raw_hex byte-by-byte; show two-row alignment with mismatches highlighted.
  const A = (a.raw_hex || '').match(/.{2}/g) || [];
  const B = (b.raw_hex || '').match(/.{2}/g) || [];
  const len = Math.max(A.length, B.length);
  let row1 = `<div style="color: var(--muted)">offset</div><div>`;
  let row2 = `<div>packet ${a.id} (${A.length}B):&nbsp;</div><div>`;
  let row3 = `<div>packet ${b.id} (${B.length}B):&nbsp;</div><div>`;
  let mismatches = 0;
  for (let i = 0; i < len; i++) {
    const av = A[i] ?? '..';
    const bv = B[i] ?? '..';
    const diff = av !== bv;
    if (diff) mismatches++;
    const idx = i.toString(16).padStart(2, '0');
    const cls = diff ? 'style="color: var(--bad); font-weight: 600;"' : '';
    row1 += `<span style="color: var(--muted); margin-right: 4px;">${idx}</span>`;
    row2 += `<span ${cls} style="margin-right: 4px;">${av}</span>`;
    row3 += `<span ${cls} style="margin-right: 4px;">${bv}</span>`;
  }
  return `
    <div style="margin-bottom: 6px;"><strong>${mismatches}</strong> bytes differ (of ${len})</div>
    <div style="font-family: 'SF Mono', monospace;">${row1}</div></div>
    <div style="font-family: 'SF Mono', monospace; margin-top: 4px;">${row2}</div></div>
    <div style="font-family: 'SF Mono', monospace;">${row3}</div></div>
  `;
}

$('#modal-annotate-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!activePacketId) return;
  const fd = new FormData(e.target);
  // Need the session_id — fetch from the packet
  const pktR = await fetch(`/api/packets/${activePacketId}`);
  const pkt = await pktR.json();
  const body = JSON.stringify({
    session_id: pkt.session_id,
    packet_id_start: pkt.id,
    packet_id_end: pkt.id,
    label: fd.get('label'),
    notes: fd.get('notes') || null,
  });
  const r = await fetch('/api/annotations', {method:'POST', headers:{'content-type':'application/json'}, body});
  if (r.ok) {
    $('#modal-annotate-result').textContent = '✓ annotation saved';
    e.target.reset();
  } else {
    $('#modal-annotate-result').textContent = 'error: ' + await r.text();
  }
});

// Roll the last-seen string every second
setInterval(() => {
  if (!lastPacketAt) return;
  const ago = Math.floor((Date.now() - lastPacketAt) / 1000);
  const el = $('#capture-last-seen');
  if (el) el.textContent = ago === 0 ? 'last: just now' : `last: ${ago}s ago`;
}, 1000);

// --- Sessions ---
$('#btn-refresh-sessions').addEventListener('click', loadSessions);

// Event delegation: bind once on the table, survives all re-renders.
$('#sessions-table').addEventListener('click', (e) => {
  const view = e.target.closest('.view-session');
  if (view) { return safeRun(() => loadSessionPackets(+view.dataset.sid)); }
  const summary = e.target.closest('.summary-session');
  if (summary) { return safeRun(() => loadHandleSummary(+summary.dataset.sid)); }
});

async function safeRun(fn) {
  try { await fn(); }
  catch (err) {
    console.error('session view failed:', err);
    $('#session-detail').innerHTML =
      `<div style="color: var(--bad); padding: 8px; border: 1px solid var(--bad); border-radius: 4px;">
        <strong>Error rendering session:</strong> ${err.message}<br>
        <small>Check browser console for stack trace. The session itself is fine — this is a UI bug.</small>
      </div>`;
  }
}

async function loadSessions() {
  const sessions = await api('/api/sessions');
  const tbody = $('#sessions-table tbody');
  tbody.innerHTML = '';
  for (const s of sessions) {
    const tr = document.createElement('tr');
    const label = (s.label || '').replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
    tr.innerHTML = `<td>${s.id}</td><td>${label}</td>
      <td>${new Date(s.started_at*1000).toLocaleString()}</td>
      <td>${s.ended_at ? new Date(s.ended_at*1000).toLocaleTimeString() : '<em>active</em>'}</td>
      <td><button data-sid="${s.id}" class="view-session">View</button>
          <button data-sid="${s.id}" class="summary-session">Summary</button>
          <a href="/api/sessions/${s.id}/export.pcap" class="chip" style="text-decoration: none; padding: 4px 8px;">pcap</a></td>`;
    tbody.appendChild(tr);
  }
}
// `filter` is {addr}, {name}, {marker: annotation_id}, or null
async function loadSessionPackets(sid, filter = null) {
  // Show loading state immediately + scroll to detail so user sees something happens
  $('#session-detail').innerHTML = `<div style="padding: 16px; color: var(--muted)">Loading session ${sid}…</div>`;
  $('#session-detail').scrollIntoView({ behavior: 'smooth', block: 'start' });
  // Backwards compat: bare string = addr
  if (typeof filter === 'string') filter = { addr: filter };
  let pkts, devices, annotations;
  if (filter?.marker) {
    // Marker-range mode: fetch packets in the annotation's range directly.
    const [markerData, devs, anns] = await Promise.all([
      api(`/api/annotations/${filter.marker}/packets?limit=500`),
      api(`/api/sessions/${sid}/devices`),
      api(`/api/sessions/${sid}/annotations`),
    ]);
    pkts = markerData.packets;
    devices = devs;
    annotations = anns;
  } else {
    const filterParams = filter
      ? (filter.addr ? `&device_addr=${encodeURIComponent(filter.addr)}` : '') +
        (filter.name ? `&device_name=${encodeURIComponent(filter.name)}` : '')
      : '';
    const q = `?limit=500${filterParams}`;
    [pkts, devices, annotations] = await Promise.all([
      api(`/api/sessions/${sid}/packets${q}`),
      api(`/api/sessions/${sid}/devices`),
      api(`/api/sessions/${sid}/annotations`),
    ]);
  }
  const markerLabel = filter?.marker
    ? (annotations.find(a => a.id === filter.marker)?.label || `#${filter.marker}`)
    : null;
  const activeStr = filter?.addr
    ? filter.addr
    : filter?.name
      ? `name="${filter.name}"`
      : markerLabel
        ? `marker="${markerLabel}"`
        : null;
  const filterMsg = activeStr
    ? `<button id="hist-clear-filter">show all</button> filtered to <code>${activeStr}</code>`
    : `${devices.length} distinct devices · ${annotations.length} markers`;
  // Build addr → name map so packet rows can render name from devices endpoint
  const nameByAddr = Object.fromEntries(devices.filter(d => d.name).map(d => [d.device_addr, d.name]));
  $('#session-detail').innerHTML =
    `<h4>Packets for session ${sid} (${pkts.length}) — click any row for details</h4>` +
    `<div style="display:flex; gap:6px; margin-bottom: 8px; align-items:center;">
      <input id="hist-filter-input" placeholder="filter: paste a BD_ADDR/UUID, or type an alias name and press Enter"
             style="flex: 1; min-width: 280px"
             value="${(filter?.addr || filter?.name || '').replace(/"/g, '&quot;')}" />
      <button type="button" id="hist-apply-filter">Apply</button>
    </div>` +
    `<div style="margin-bottom: 8px;">${filterMsg}</div>` +
    (annotations.length ? `<div id="hist-marker-panel" style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:10px; align-items:center;">
      <small style="color: var(--muted)">markers:</small>` +
      annotations.map(a =>
        `<button class="chip ${a.id === filter?.marker ? 'active' : ''}" data-marker="${a.id}" title="${(a.notes||'').replace(/"/g,'&quot;')}">
          ▶ <strong>${a.label}</strong> (${a.packet_id_end - a.packet_id_start + 1})
         </button>`
      ).join('') +
      (annotations.length >= 2 ? `
        <span style="margin-left:12px; color: var(--muted)">diff:</span>
        <select id="hist-diff-baseline"><option value="">— baseline —</option>` +
        annotations.map(a => `<option value="${a.id}">${a.label}</option>`).join('') +
        `</select>
        <select id="hist-diff-candidate"><option value="">— candidate —</option>` +
        annotations.map(a => `<option value="${a.id}">${a.label}</option>`).join('') +
        `</select>
        <button type="button" id="hist-diff-run">Run diff</button>` : '') +
    `</div>` : '') +
    `<div id="hist-device-panel" style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:10px;">` +
    devices.slice(0, 30).map(d =>
      `<button class="chip ${d.device_addr === filter?.addr ? 'active' : ''}" data-addr="${d.device_addr}">
        ${d.name ? `<strong>${d.name}</strong> ` : ''}${d.device_addr} · ${d.n}
       </button>`
    ).join('') +
    (devices.length > 30 ? `<span class="hint" style="margin-left:8px">… and ${devices.length-30} more</span>` : '') +
    `</div>` +
    `<table id="hist-packets"><thead><tr><th>id</th><th>ts</th><th>device</th><th>conn</th><th>dir</th><th>pdu</th><th>handle</th><th>payload</th></tr></thead><tbody>` +
    pkts.map(p => {
      const nm = p.device_addr ? nameByAddr[p.device_addr] : null;
      const devCell = p.device_addr
        ? (nm
            ? `<strong>${nm}</strong><br><code style="font-size:10px; color:var(--muted)">${p.device_addr}</code>`
            : `<code style="font-size:11px">${p.device_addr}</code>`)
        : '';
      return `<tr data-pid="${p.id}" style="cursor:pointer">
        <td>${p.id}</td><td>${p.ts?.toFixed(3)}</td>
        <td>${devCell}</td>
        <td>${p.conn_handle??''}</td><td>${p.direction??''}</td>
        <td>${p.pdu_type??''}</td><td>${p.handle??''}</td>
        <td><code>${p.payload_hex??''}</code></td>
      </tr>`;
    }).join('') +
    `</tbody></table>`;
  for (const tr of $$('#hist-packets tbody tr')) {
    tr.addEventListener('click', () => openPacketDetail(+tr.dataset.pid));
  }
  for (const b of $$('#hist-device-panel .chip')) {
    b.addEventListener('click', async (e) => {
      if (e.shiftKey) {
        await renameAddr(b.dataset.addr);
        loadSessionPackets(sid, filter);
      } else {
        loadSessionPackets(sid, { addr: b.dataset.addr });
      }
    });
  }
  $('#hist-clear-filter')?.addEventListener('click', () => loadSessionPackets(sid, null));

  const applyHistFilter = () => {
    const v = $('#hist-filter-input').value.trim();
    if (!v) return loadSessionPackets(sid, null);
    // Auto-detect: MAC (AA:BB:CC:DD:EE:FF) or CB UUID (8-4-4-4-12 hex) → addr; otherwise treat as name.
    const isMAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(v);
    const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
    return loadSessionPackets(sid, isMAC || isUUID ? { addr: v } : { name: v });
  };
  $('#hist-apply-filter')?.addEventListener('click', applyHistFilter);
  $('#hist-filter-input')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); applyHistFilter(); }
  });

  // Marker chips: click → filter session to that marker's packet range
  for (const b of $$('#hist-marker-panel .chip')) {
    b.addEventListener('click', () => loadSessionPackets(sid, { marker: +b.dataset.marker }));
  }
  // Diff-run button: compute marker-vs-marker diff and show result inline
  $('#hist-diff-run')?.addEventListener('click', async () => {
    const baseline = +$('#hist-diff-baseline').value;
    const candidate = +$('#hist-diff-candidate').value;
    if (!baseline || !candidate) {
      alert('Pick a baseline and candidate marker first.');
      return;
    }
    const r = await fetch('/api/marker_diff', {
      method: 'POST', headers: {'content-type': 'application/json'},
      body: JSON.stringify({baseline_annotation_id: baseline, candidate_annotation_id: candidate}),
    });
    const j = await r.json();
    const tbody = $('#hist-packets tbody');
    tbody.innerHTML = j.new_packets.map(p =>
      `<tr data-pid="${p.id}" style="cursor:pointer">
        <td>${p.id}</td><td>${p.ts?.toFixed(3)}</td>
        <td><code style="font-size:11px">${p.device_addr??''}</code></td>
        <td>${p.conn_handle??''}</td><td>${p.direction??''}</td>
        <td>${p.pdu_type??''}</td><td>${p.handle??''}</td>
        <td><code>${p.payload_hex??''}</code></td>
      </tr>`
    ).join('') || '<tr><td colspan=8><em>No new packets — candidate is a subset of baseline.</em></td></tr>';
    for (const tr of $$('#hist-packets tbody tr')) {
      if (tr.dataset.pid) tr.addEventListener('click', () => openPacketDetail(+tr.dataset.pid));
    }
    // Headline up top
    const h = document.createElement('div');
    h.style.cssText = 'background: var(--panel-2); padding: 8px; border-radius: 4px; margin: 8px 0;';
    h.innerHTML = `<strong>${j.new_packet_count}</strong> new packets in <code>${j.candidate.label}</code> not seen in <code>${j.baseline.label}</code>`;
    $('#hist-marker-panel').after(h);
  });
}
async function loadHandleSummary(sid) {
  $('#session-detail').innerHTML = `<div style="padding: 16px; color: var(--muted)">Loading summary for session ${sid}…</div>`;
  $('#session-detail').scrollIntoView({ behavior: 'smooth', block: 'start' });
  const summary = await api(`/api/handle_summary/${sid}`);
  $('#session-detail').innerHTML =
    `<h4>Handle summary for session ${sid}</h4>` +
    `<table id="hs-table"><thead><tr><th>handle</th><th>dir</th><th>n</th><th>unique</th><th>avg len</th><th>byte variability</th><th>actions</th></tr></thead><tbody>` +
    summary.map(s =>
      `<tr><td>${s.handle}</td><td>${s.direction??''}</td><td>${s.count}</td><td>${s.unique_payloads}</td><td>${s.avg_len.toFixed(1)}</td><td>${s.byte_variability.map(v => v.toFixed(2)).join(' ')}</td>
       <td><button class="hs-checksum" data-handle="${s.handle}" data-dir="${s.direction??''}">Find checksum</button></td></tr>`
    ).join('') +
    `</tbody></table>` +
    `<pre id="hs-checksum-result" style="margin-top: 12px;"></pre>`;
  for (const b of $$('#hs-table .hs-checksum')) {
    b.addEventListener('click', async () => {
      $('#hs-checksum-result').textContent = 'searching…';
      const q = `handle=${b.dataset.handle}` + (b.dataset.dir ? `&direction=${encodeURIComponent(b.dataset.dir)}` : '');
      const hyp = await api(`/api/checksum_hypotheses/${sid}?${q}`);
      if (!hyp.length) {
        $('#hs-checksum-result').textContent = `No checksum hypothesis matched for handle ${b.dataset.handle}.`;
        return;
      }
      $('#hs-checksum-result').textContent =
        `Top ${hyp.length} hypothesis for handle ${b.dataset.handle}:\n\n` +
        hyp.map((h, i) =>
          `${i+1}. ${h.algo}(payload[${h.input_start}:${h.input_end}]) → payload[${h.output_offset}${h.output_size>1?':'+(h.output_offset+h.output_size):''}]   (verified across ${h.sample_count} packets)`
        ).join('\n');
    });
  }
}

// --- Diff ---
$('#diff-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = JSON.stringify({baseline: +fd.get('baseline'), candidate: +fd.get('candidate')});
  const r = await api('/api/diff', {method:'POST', body});
  $('#diff-result').textContent = JSON.stringify(r, null, 2);
});

// --- Replay ---
$('#replay-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = JSON.stringify({
    target: fd.get('target'),
    steps: JSON.parse(fd.get('steps')),
    listen_for_notifications_ms: +fd.get('listen_for_notifications_ms'),
  });
  $('#replay-result').textContent = '...';
  const r = await api('/api/replay', {method:'POST', body});
  $('#replay-result').textContent = JSON.stringify(r, null, 2);
});

// ---- Global keyboard shortcuts ----
// j/k = navigate live feed packets, x = mark, / = focus filter, esc = close modal, ? = help
const KEY_HELP = `
Keyboard shortcuts
──────────────────
  j / k    next / previous packet in live feed
  Enter    open detail for highlighted packet
  x        focus "Mark now" label input
  /        focus live filter
  Esc      close modal / clear filter
  ?        toggle this help
`.trim();

let highlightedRowIdx = -1;
function highlightLiveRow(idx) {
  const trs = $$('#live-packets tbody tr:not(.marker)').filter ? $$('#live-packets tbody tr:not(.marker)') : Array.from(document.querySelectorAll('#live-packets tbody tr:not(.marker)'));
  const visible = trs.filter(tr => tr.style.display !== 'none');
  if (!visible.length) return;
  idx = Math.max(0, Math.min(visible.length - 1, idx));
  visible.forEach(tr => tr.style.outline = '');
  visible[idx].style.outline = '2px solid var(--accent)';
  visible[idx].scrollIntoView({ block: 'nearest' });
  highlightedRowIdx = idx;
}

document.addEventListener('keydown', (e) => {
  // Skip shortcut handling if user is typing in an input/textarea/select
  const tag = (e.target.tagName || '').toLowerCase();
  if (tag === 'input' || tag === 'textarea' || tag === 'select') {
    if (e.key === 'Escape') e.target.blur();
    return;
  }
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  if (e.key === 'j') { e.preventDefault(); highlightLiveRow(highlightedRowIdx + 1); }
  else if (e.key === 'k') { e.preventDefault(); highlightLiveRow(highlightedRowIdx - 1); }
  else if (e.key === 'Enter') {
    const tr = document.querySelector('#live-packets tbody tr[style*="outline"]');
    if (tr?.dataset?.packetId) openPacketDetail(+tr.dataset.packetId);
  }
  else if (e.key === 'x') { e.preventDefault(); $('#marker-form input[name=label]')?.focus(); }
  else if (e.key === '/') { e.preventDefault(); $('#live-filter-text')?.focus(); }
  else if (e.key === 'Escape') {
    if (!$('#packet-modal').classList.contains('hidden')) {
      $('#packet-modal').classList.add('hidden');
    } else {
      $('#live-filter-clear')?.click();
    }
  }
  else if (e.key === '?') { e.preventDefault(); toggleKeyHelp(); }
});

function toggleKeyHelp() {
  let el = document.getElementById('key-help-overlay');
  if (el) { el.remove(); return; }
  el = document.createElement('pre');
  el.id = 'key-help-overlay';
  el.style.cssText = 'position:fixed; bottom: 16px; right: 16px; background: var(--panel); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 12px; z-index: 200; font-family: SF Mono, monospace; font-size: 12px;';
  el.textContent = KEY_HELP;
  document.body.appendChild(el);
}

$('#sweep-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const data = Object.fromEntries(fd);
  for (const k of ['offset', 'step', 'value_start', 'value_end', 'delay_ms', 'listen_ms_per_step']) {
    if (data[k] !== '') data[k] = +data[k];
  }
  data.base_payload_hex = (data.base_payload_hex || '').replace(/\s/g, '');
  $('#sweep-result').textContent = 'sweeping…';
  try {
    const r = await fetch('/api/replay/sweep', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(data)});
    const json = await r.json();
    $('#sweep-result').textContent = JSON.stringify(json, null, 2);
  } catch (err) {
    $('#sweep-result').textContent = 'failed: ' + err.message;
  }
});

// --- Protocol Dict ---
$('#btn-refresh-proto').addEventListener('click', loadProtocolEntries);
async function loadProtocolEntries() {
  const entries = await api('/api/protocol_entries');
  const tbody = $('#protocol-table tbody');
  tbody.innerHTML = entries.map(e =>
    `<tr><td>${e.device_name??''}</td><td>${e.handle}</td><td>${e.direction}</td><td>${e.name}</td><td>${e.confidence}</td><td>${e.notes??''}</td></tr>`
  ).join('');
}
$('#proto-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = JSON.stringify({
    device_name: fd.get('device_name') || null,
    handle: +fd.get('handle'),
    direction: fd.get('direction'),
    name: fd.get('name'),
    structure: JSON.parse(fd.get('structure') || '[]'),
    decoder_py: fd.get('decoder_py') || null,
    confidence: +fd.get('confidence'),
  });
  await api('/api/protocol_entries', {method:'POST', body});
  loadProtocolEntries();
});

// --- Integrations ---
async function loadIntegrations() {
  const devices = await api('/api/integrations/devices');
  $('#integrations-devices tbody').innerHTML = devices.map(d =>
    `<tr><td>${d.device_name}</td><td>${d.entries}</td>
      <td><button class="pick-device" data-name="${d.device_name}">Use</button></td></tr>`
  ).join('') || '<tr><td colspan=3><em>None yet. Add some protocol entries first.</em></td></tr>';
  $$('.pick-device').forEach(b => b.addEventListener('click', () => {
    $('#export-driver-form [name=device_name]').value = b.dataset.name;
    $('#scaffold-ha-form [name=device_name]').value = b.dataset.name;
  }));
  const vocab = await api('/api/integrations/vocabulary');
  $('#vocab-block').textContent = JSON.stringify(vocab, null, 2);
}
$('#export-driver-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = JSON.stringify(Object.fromEntries(fd));
  const r = await api('/api/integrations/export_driver', {method:'POST', body});
  $('#driver-result').textContent = `wrote ${r.path} (${r.bytes} bytes)\n\n${r.code}`;
});
$('#scaffold-ha-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const data = Object.fromEntries(fd);
  if (data.manufacturer_id === '') delete data.manufacturer_id; else data.manufacturer_id = +data.manufacturer_id;
  for (const k of ['local_name', 'service_uuid']) { if (data[k] === '') delete data[k]; }
  const body = JSON.stringify(data);
  const r = await api('/api/integrations/scaffold_ha', {method:'POST', body});
  $('#scaffold-result').textContent = `Component dir: ${r.component_dir}\n\n` + r.paths.join('\n');
});

// --- LTK management ---
async function loadLTKs() {
  try {
    const r = await fetch('/api/ltks');
    const rows = await r.json();
    $('#ltk-list tbody').innerHTML = rows.length
      ? rows.map(r => `<tr><td><code>${r.device_addr}</code></td><td><code>${r.ltk_hex}</code></td><td>${r.notes ?? ''}</td></tr>`).join('')
      : '<tr><td colspan=3><em>No LTKs stored.</em></td></tr>';
  } catch (_) {}
}
$('#ltk-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const data = Object.fromEntries(fd);
  await fetch('/api/ltk', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(data)});
  e.target.reset();
  loadLTKs();
});

// --- Dongle / Flash ---
async function loadDongleInfo() {
  const h = await loadHealth();
  $('#dongle-info').innerHTML = `
    <span>dongle port</span><span>${h.dongle_port ?? '<em>not detected</em>'}</span>
    <span>nrfutil ble-sniffer</span><span>${h.nrfutil_binary ?? '<em>not found — install nrfutil 8.x + `nrfutil install ble-sniffer`</em>'}</span>
    <span>legacy extcap script</span><span>${h.extcap_script || '<em>—</em>'}</span>
    <span>wireshark</span><span>${h.wireshark_present ? 'present' : 'absent (optional)'}</span>
    <span>PacketLogger CLI</span><span>${h.packetlogger_cli ?? (h.packetlogger_app_present ? '<em>app only — use GUI + import</em>' : '<em>not installed</em>')}</span>
  `;
}
$('#flash-bundle-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const log = $('#flash-log');
  log.textContent = 'uploading bundle…';
  try {
    const r = await fetch('/api/flash/upload', {method:'POST', body: fd});
    const json = await r.json();
    log.textContent =
      (json.ok ? '✓ ' : '✗ ') + json.message + '\n\n' +
      (json.events || []).map(ev =>
        (ev.percent != null ? `[${Math.round(ev.percent*100)}%] ` : '') + ev.message
      ).join('\n');
    loadDongleInfo();
  } catch (err) {
    log.textContent = 'upload+flash failed: ' + err.message;
  }
});

$('#btn-flash').addEventListener('click', () => {
  const log = $('#flash-log');
  log.textContent = '';
  const es = new EventSource('/api/flash');
  // EventSource only supports GET; SSE expects EventSource but our endpoint is POST.
  // Fall back to fetch streaming:
  es.close();
  fetch('/api/flash', {method:'POST'}).then(async (r) => {
    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      buf += decoder.decode(value, {stream:true});
      const parts = buf.split('\n\n');
      buf = parts.pop();
      for (const p of parts) {
        if (p.startsWith('data: ')) {
          const ev = JSON.parse(p.slice(6));
          log.textContent += (ev.percent != null ? `[${Math.round(ev.percent*100)}%] ` : '') + ev.message + '\n';
          log.scrollTop = log.scrollHeight;
        }
      }
    }
    loadDongleInfo();
  });
});
