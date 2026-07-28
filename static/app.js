const state = { devices: [], results: [], jobId: null, socket: null, logAlerts: 0, jobFinished: true, reconnectAttempts: 0, reconnectTimer: null };
const $ = (id) => document.getElementById(id);
const LAST_JOB_KEY = 'nas-last-job';

const DEVICE_TYPE_PRESETS = [
  { value: 'cisco_ios', label: 'Cisco IOS / IOS-XE / C9800 WLC' },
  { value: 'cisco_nxos', label: 'Cisco Nexus (NX-OS)' },
  { value: 'cisco_wlc', label: 'Cisco AireOS WLC (5500/8500/WiSM2)' },
  { value: 'generic_termserver', label: 'APC PDU (AOS)' },
];
function isKnownDeviceType(value) { return DEVICE_TYPE_PRESETS.some(p => p.value === value); }

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}
function renderDevices() {
  $('device-count').textContent = `${state.devices.length} device${state.devices.length === 1 ? '' : 's'}`;
  $('device-body').innerHTML = state.devices.map((d, i) => {
    const type = d.device_type == null ? 'cisco_ios' : d.device_type;
    const known = isKnownDeviceType(type);
    const options = DEVICE_TYPE_PRESETS.map(p => `<option value="${p.value}"${type === p.value ? ' selected' : ''}>${escapeHtml(p.label)}</option>`).join('');
    return `
    <tr>
      <td><input class="table-input" data-index="${i}" data-field="name" value="${escapeHtml(d.name)}"></td>
      <td><input class="table-input" data-index="${i}" data-field="host" value="${escapeHtml(d.host)}"></td>
      <td><input class="table-input" data-index="${i}" data-field="port" value="${escapeHtml(d.port || 22)}"></td>
      <td class="device-type-cell">
        <select class="table-input device-type-select" data-index="${i}">
          ${options}
          <option value="__other__"${known ? '' : ' selected'}>Other (type manually)…</option>
        </select>
        <input class="table-input device-type-other${known ? ' hidden' : ''}" data-index="${i}" placeholder="netmiko device type" value="${known ? '' : escapeHtml(type)}">
      </td>
      <td><button class="delete-row" data-delete="${i}" title="Remove">×</button></td>
    </tr>`;
  }).join('');
  document.querySelectorAll('.table-input[data-field]').forEach(input => input.addEventListener('input', e => {
    const i = Number(e.target.dataset.index); state.devices[i][e.target.dataset.field] = e.target.value;
  }));
  document.querySelectorAll('.device-type-select').forEach(select => select.addEventListener('change', e => {
    const i = Number(e.target.dataset.index);
    if (e.target.value === '__other__') {
      state.devices[i].device_type = '';
      renderDevices();
      document.querySelector(`.device-type-other[data-index="${i}"]`)?.focus();
    } else {
      state.devices[i].device_type = e.target.value;
    }
  }));
  document.querySelectorAll('.device-type-other').forEach(input => input.addEventListener('input', e => {
    const i = Number(e.target.dataset.index); state.devices[i].device_type = e.target.value;
  }));
  document.querySelectorAll('[data-delete]').forEach(btn => btn.addEventListener('click', () => {
    state.devices.splice(Number(btn.dataset.delete), 1); renderDevices();
  }));
}
function addDevice(device = {name:'', host:'', port:22, device_type:'cisco_ios'}) { state.devices.push(device); renderDevices(); }
function parseCsv(text) {
  const lines = text.replace(/\r/g,'').split('\n').filter(Boolean);
  if (!lines.length) return [];
  const headers = lines.shift().split(',').map(v => v.trim().toLowerCase());
  return lines.map(line => {
    const parts = line.split(',').map(v => v.trim());
    const row = {}; headers.forEach((h,i) => row[h] = parts[i] ?? '');
    return {name: row.name || row.hostname || row.host, host: row.host || row.ip || row.address, port: row.port || 22, device_type: row.device_type || 'cisco_ios'};
  }).filter(d => d.host);
}
function openModal(title, html) { $('modal-title').textContent = title; $('modal-body').innerHTML = html; $('modal').classList.remove('hidden'); }
function closeModal() { $('modal').classList.add('hidden'); }
function showError(message) { openModal('Unable to continue', `<div class="error-banner">${escapeHtml(message)}</div><div class="modal-actions"><button class="button primary" onclick="document.getElementById('modal').classList.add('hidden')">Close</button></div>`); }

$('add-device').addEventListener('click', () => addDevice());
$('load-example').addEventListener('click', () => { state.devices = [{name:'USLIAP01SWA055',host:'192.0.2.55',port:22,device_type:'cisco_ios'},{name:'USLIAP01SWC001',host:'192.0.2.10',port:22,device_type:'cisco_ios'},{name:'USLIAP01NXA001',host:'192.0.2.20',port:22,device_type:'cisco_nxos'},{name:'USLIAP01WLC001',host:'192.0.2.30',port:22,device_type:'cisco_wlc'},{name:'USLIAP01PDU001',host:'192.0.2.40',port:22,device_type:'generic_termserver'}]; renderDevices(); });

$('download-template').addEventListener('click', () => {
  const rows = [
    ['name', 'host', 'port', 'device_type'],
    ['CORE-SWITCH-01', '192.0.2.10', '22', 'cisco_ios'],
    ['NEXUS-SWITCH-01', '192.0.2.20', '22', 'cisco_nxos'],
    ['WLC-5520-01', '192.0.2.30', '22', 'cisco_wlc'],
    ['PDU-01', '192.0.2.40', '22', 'generic_termserver'],
  ];
  const csv = rows.map(row => row.join(',')).join('\r\n') + '\r\n';
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'device-list-template.csv';
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
});
$('csv-file').addEventListener('change', async e => { const file=e.target.files[0]; if(file){ state.devices=parseCsv(await file.text()); renderDevices(); } });
$('paste-devices').addEventListener('click', () => {
  openModal('Paste devices', `<p class="help">Paste one device per line. Supported formats: <code>name,ip</code> or just <code>ip</code>.</p><textarea id="paste-area" rows="10" style="width:100%" placeholder="SWA001,10.10.10.11\nSWA002,10.10.10.12"></textarea><div class="modal-actions"><button class="button secondary" id="paste-cancel">Cancel</button><button class="button primary" id="paste-add">Add devices</button></div>`);
  $('paste-cancel').onclick=closeModal;
  $('paste-add').onclick=()=>{ const rows=$('paste-area').value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean); rows.forEach(line=>{const parts=line.split(',').map(v=>v.trim()); addDevice(parts.length>1?{name:parts[0],host:parts[1],port:22,device_type:'cisco_ios'}:{name:parts[0],host:parts[0],port:22,device_type:'cisco_ios'});}); closeModal(); };
});
$('modal-close').addEventListener('click', closeModal);
$('modal').addEventListener('click', e => { if(e.target === $('modal')) closeModal(); });

function buildForm(devices = state.devices) {
  const form = new FormData();
  form.append('devices_json', JSON.stringify(devices.map(d=>({...d, port:Number(d.port||22), device_type:d.device_type||'cisco_ios'}))));
  form.append('username', $('username').value);
  form.append('password', $('password').value);
  form.append('enable_secret', $('enable-secret').value);
  form.append('concurrent_devices', $('concurrent-devices').value);
  const sequentialAuthentication = $('sequential-authentication')?.checked ?? true;
  form.append('sequential_authentication', sequentialAuthentication ? 'true' : 'false');
  form.append('auth_timeout', $('auth-timeout').value);
  form.append('custom_commands_json', JSON.stringify(getCustomCommands()));
  return form;
}
async function startJob(devices = state.devices) {
  if (!devices.length) return showError('Add at least one device.');
  if (!$('username').value.trim() || !$('password').value) return showError('Enter the SSH username and password.');
  $('start-job').disabled=true;
  try {
    const response = await fetch('/api/jobs',{method:'POST',body:buildForm(devices)});
    const payload = await response.json();
    if(!response.ok) throw new Error(payload.detail || 'Unable to create collection job');
    state.jobId=payload.job_id; state.results=[]; state.logAlerts=0; state.jobFinished=false; state.reconnectAttempts=0;
    localStorage.setItem(LAST_JOB_KEY, state.jobId);
    $('log-alert-banner').classList.add('hidden'); $('log-alert-text').textContent='';
    $('progress-card').classList.remove('hidden'); $('download-row').classList.add('hidden');
    $('connection-status').classList.add('hidden');
    $('cancel-job').classList.remove('hidden'); $('cancel-job').disabled=false; $('cancel-job').textContent='Cancel job';
    $('result-body').innerHTML=''; $('live-log').textContent=''; $('job-state').textContent='Running';
    window.scrollTo({top:$('progress-card').offsetTop-20,behavior:'smooth'});
    connectSocket();
  } catch(error) { showError(error.message); $('start-job').disabled=false; }
}
$('start-job').addEventListener('click',()=>startJob());

function connectSocket() {
  if (state.reconnectTimer) { clearTimeout(state.reconnectTimer); state.reconnectTimer = null; }
  if (state.socket) { state.socket.onclose = null; state.socket.close(); }
  const scheme=location.protocol==='https:'?'wss':'ws';
  const socket = new WebSocket(`${scheme}://${location.host}/ws/jobs/${state.jobId}`);
  state.socket = socket;
  socket.onopen = () => {
    state.reconnectAttempts = 0;
    $('connection-status').classList.add('hidden');
  };
  socket.onmessage = e => handleEvent(JSON.parse(e.data));
  socket.onclose = () => {
    if (state.jobFinished || state.socket !== socket) return;
    state.reconnectAttempts += 1;
    $('connection-status').classList.remove('hidden');
    $('connection-status').textContent = `Live connection lost — reconnecting… (attempt ${state.reconnectAttempts})`;
    const delay = Math.min(1000 * (2 ** Math.min(state.reconnectAttempts, 5)), 15000);
    state.reconnectTimer = setTimeout(() => { if (!state.jobFinished) connectSocket(); }, delay);
  };
}
function appendLog(message) { const now=new Date().toLocaleTimeString(); $('live-log').textContent += `${now}  ${message}\n`; $('live-log').scrollTop=$('live-log').scrollHeight; }
function handleEvent(event) {
  if(event.type==='log') appendLog(event.message);
  if(event.type==='job_started') { $('progress-number').textContent=`0 / ${event.total}`; }
  if(event.type==='device_update') { const r=event.result; state.results[r.index]=r; renderResults(); }
  if(event.type==='log_alert') {
    state.logAlerts += Number(event.count || 0);
    $('log-alert-banner').classList.remove('hidden');
    $('log-alert-text').textContent = `${state.logAlerts} potential operational issue${state.logAlerts === 1 ? '' : 's'} detected. Highest reported severity includes ${event.highest_severity}. Review the Log Alerts workbook sheet and raw show logging output.`;
  }
  if(event.type==='progress') {
    $('progress-number').textContent=`${event.complete} / ${event.total}`; $('success-number').textContent=event.successful; $('failed-number').textContent=event.failed;
    $('progress-bar').style.width=`${event.total ? (event.complete/event.total)*100 : 0}%`;
  }
  if(event.type==='job_complete') {
    state.jobFinished = true;
    if (state.reconnectTimer) { clearTimeout(state.reconnectTimer); state.reconnectTimer = null; }
    $('connection-status').classList.add('hidden');
    $('cancel-job').classList.add('hidden');
    const statusLabel = event.status === 'CANCELLED' ? 'Cancelled' : event.status === 'FAILED' ? 'Failed' : 'Complete';
    $('job-state').textContent = statusLabel;
    $('download-row').classList.remove('hidden'); $('start-job').disabled=false;
    const cancelledCount = Number(event.cancelled || 0);
    appendLog(`Job ${statusLabel.toLowerCase()}: ${event.successful} successful, ${event.failed} failed${cancelledCount ? `, ${cancelledCount} cancelled` : ''}, ${state.logAlerts} log alert(s).`);
  }
}
$('cancel-job').addEventListener('click', async () => {
  if (!state.jobId) return;
  $('cancel-job').disabled = true;
  $('cancel-job').textContent = 'Cancelling…';
  try {
    const response = await fetch(`/api/jobs/${state.jobId}/cancel`, {method:'POST'});
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.detail || 'Unable to cancel job');
    }
    appendLog('Cancellation requested. Devices already collecting will wrap up shortly.');
  } catch (error) {
    showError(error.message);
    $('cancel-job').disabled = false;
    $('cancel-job').textContent = 'Cancel job';
  }
});
function renderResults() {
  $('result-body').innerHTML=state.results.filter(Boolean).map(r=>{
    const cls=r.status==='SUCCESS'?'status-success':r.status==='FAILED'?'status-failed':r.status==='CANCELLED'?'status-cancelled':'status-running';
    const label=(r.status==='FAILED'||r.status==='CANCELLED')?(r.error?`${r.status}: ${escapeHtml(r.error)}`:r.status):r.status;
    const logHealth = Number(r.log_alert_count || 0) > 0 ? `<span class="log-health-alert">⚠ ${r.log_alert_count} (${escapeHtml(r.log_highest_severity || 'Warning')})</span>` : (r.status === 'SUCCESS' ? '<span class="log-health-ok">No alerts</span>' : '—');
    return `<tr><td>${escapeHtml(r.detected_hostname||r.inventory_name)}</td><td>${escapeHtml(r.host)}</td><td>${escapeHtml(r.model||'—')}</td><td>${escapeHtml(r.software_version||'—')}</td><td>${logHealth}</td><td class="${cls}">${label}</td></tr>`;
  }).join('');
}
$('download-zip').onclick=()=>location.href=`/api/jobs/${state.jobId}/download`;
$('download-xlsx').onclick=()=>location.href=`/api/jobs/${state.jobId}/technical-review.xlsx`;
$('download-csv').onclick=()=>location.href=`/api/jobs/${state.jobId}/results.csv`;
$('retry-failed').onclick=async()=>{
  const failedCount = state.results.filter(r => r && (r.status === 'FAILED' || r.status === 'CANCELLED')).length;
  if (!failedCount) return showError('There are no failed or cancelled devices to retry.');
  if (!$('username').value.trim() || !$('password').value) return showError('Enter the SSH username and password.');
  if (!state.jobId) return showError('No active job to retry - reopen it from History first.');

  const form = new FormData();
  form.append('username', $('username').value);
  form.append('password', $('password').value);
  form.append('enable_secret', $('enable-secret').value);

  $('retry-failed').disabled = true;
  try {
    const response = await fetch(`/api/jobs/${state.jobId}/retry`, { method: 'POST', body: form });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || 'Unable to retry this job');

    // Deliberately do NOT reset state.results or state.jobId here - retrying
    // continues the SAME job, so every already-successful device's result
    // (and its place in the downloadable outputs) is kept exactly as-is;
    // only the retried devices' rows will update as they re-run.
    state.jobFinished = false; state.reconnectAttempts = 0;
    $('download-row').classList.add('hidden');
    $('cancel-job').classList.remove('hidden'); $('cancel-job').disabled = false; $('cancel-job').textContent = 'Cancel job';
    $('job-state').textContent = 'Running';
    $('connection-status').classList.add('hidden');
    appendLog(`Retrying ${payload.retrying_count} device(s); ${payload.kept_count} already-successful device(s) kept.`);
    connectSocket();
  } catch (error) {
    showError(error.message);
  } finally {
    $('retry-failed').disabled = false;
  }
};
$('view-configs').onclick=async()=>{
  const response=await fetch(`/api/jobs/${state.jobId}/files`); const data=await response.json();
  const buttons=data.files.map(path=>`<button class="file-item" data-file="${escapeHtml(path)}">${escapeHtml(path)}</button>`).join('');
  openModal('Collected files', `<div class="file-list">${buttons||'<p>No text files found.</p>'}</div><textarea id="config-view" class="config-view" readonly placeholder="Select a file to preview"></textarea>`);
  document.querySelectorAll('[data-file]').forEach(btn=>btn.onclick=async()=>{ const r=await fetch(`/api/jobs/${state.jobId}/file?path=${encodeURIComponent(btn.dataset.file)}`); const file=await r.json(); $('config-view').value=file.content; });
};

const JOB_STATE_LABELS = { RUNNING: 'Running', QUEUED: 'Queued', COMPLETE: 'Complete', FAILED: 'Failed', CANCELLED: 'Cancelled', INTERRUPTED: 'Interrupted' };

async function restoreJob(jobId) {
  let job;
  try {
    const response = await fetch(`/api/jobs/${jobId}`);
    if (!response.ok) { localStorage.removeItem(LAST_JOB_KEY); return; }
    job = await response.json();
  } catch {
    return;
  }

  state.jobId = jobId;
  state.results = [];
  (job.results || []).forEach(r => { state.results[r.index] = r; });
  state.devices = (job.devices || []).map(d => ({...d}));
  state.jobFinished = !['RUNNING', 'QUEUED'].includes(job.status);
  renderDevices();

  const total = (job.devices || []).length || 1;
  const completeCount = (job.results || []).length;
  $('progress-card').classList.remove('hidden');
  $('progress-number').textContent = `${completeCount} / ${(job.devices || []).length}`;
  $('success-number').textContent = state.results.filter(r => r && r.status === 'SUCCESS').length;
  $('failed-number').textContent = state.results.filter(r => r && r.status === 'FAILED').length;
  $('progress-bar').style.width = `${(completeCount / total) * 100}%`;
  $('job-state').textContent = JOB_STATE_LABELS[job.status] || job.status;
  renderResults();

  if (job.results_path || job.workbook_path || job.zip_path) {
    $('download-row').classList.remove('hidden');
  } else {
    $('download-row').classList.add('hidden');
  }

  if (['RUNNING', 'QUEUED'].includes(job.status)) {
    $('cancel-job').classList.remove('hidden'); $('cancel-job').disabled = false; $('cancel-job').textContent = 'Cancel job';
    $('live-log').textContent = '';
    appendLog('Reconnected to an in-progress job.');
    connectSocket();
  } else {
    $('cancel-job').classList.add('hidden');
    $('connection-status').classList.add('hidden');
    localStorage.setItem(LAST_JOB_KEY, jobId);
  }
}

function formatJobDate(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

function renderHistory(jobsList) {
  $('history-empty').classList.toggle('hidden', jobsList.length > 0);
  $('history-body').innerHTML = jobsList.map(job => {
    const statusClass = `status-${(job.status || '').toLowerCase()}`;
    const actions = [`<button class="button secondary" data-open="${job.id}">Open</button>`];
    if (job.has_zip) actions.push(`<a class="button ghost" href="/api/jobs/${job.id}/download">ZIP</a>`);
    if (job.has_workbook) actions.push(`<a class="button ghost" href="/api/jobs/${job.id}/technical-review.xlsx">Workbook</a>`);
    return `<tr>
      <td>${formatJobDate(job.created_at)}</td>
      <td>${job.device_count}</td>
      <td><span class="job-status-tag ${statusClass}">${escapeHtml(job.status || '')}</span></td>
      <td>${job.successful}</td>
      <td>${job.failed}</td>
      <td>${job.cancelled}</td>
      <td><div class="history-actions">${actions.join('')}</div></td>
    </tr>`;
  }).join('');
  document.querySelectorAll('[data-open]').forEach(btn => btn.addEventListener('click', () => {
    showAppView('collector');
    restoreJob(btn.dataset.open);
  }));
}

async function loadHistory() {
  try {
    const response = await fetch('/api/jobs');
    const payload = await response.json();
    renderHistory(payload.jobs || []);
  } catch {
    showError('Unable to load job history.');
  }
}

const CORE_PROFILES = {
  catalyst: [
    'terminal length 0','show version','show inventory','show running-config','show startup-config','show logging',
    'show cdp neighbors','show cdp neighbors detail','show lldp neighbors','show lldp neighbors detail','show vlan',
    'show etherchannel summary','show interfaces trunk','show interfaces status','show interfaces brief','show ip interface brief',
    'show interfaces','show mac address-table','show spanning-tree','show spanning-tree blockedports','show ip arp',
    'show ip route summary','show ip route 0.0.0.0','show ip eigrp neighbors','show ip eigrp interfaces',
    'show ip ospf neighbor','show ip ospf interface','show ip bgp summary','show ip bgp neighbors',
    'show ip bgp 0.0.0.0/0','show ip mroute','show ip pim interface brief','show class-map','show policy-map',
    'show policy-map interface','show module','show power','show environment all','show power inline',
    'show environment temperature status'
  ],
  wlc: [
    'terminal length 0','show version','show inventory','show running-config','show startup-config','show logging',
    'show ap summary','show ap config general','show ap inventory all','show ap uptime','show ap image',
    'show ap tag summary','show wireless stats ap join summary','show ap dot11 24ghz summary',
    'show ap dot11 5ghz summary','show wireless client summary','show wireless stats client detail'
  ],
  nexus: [
    'terminal length 0','show version','show inventory','show running-config','show startup-config','show logging',
    'show interface mgmt0','show vpc brief','show port-channel summary','show vlan','show interfaces trunk',
    'show interface status','show interface brief','show ip interface brief','show interface','show mac address-table',
    'show spanning-tree','show ip arp','show ip route summary','show module','show power','show environment'
  ]
};

function getCustomCommands() {
  return ($('custom-commands')?.value || '').split(/\r?\n/).map(v => v.trim()).filter(Boolean);
}
function saveCustomCommands() {
  const commands = getCustomCommands();
  const invalid = commands.find(command => !/^(show|sh|terminal)\s+/i.test(command));
  if (invalid) return showError(`Only read-only show commands are allowed: ${invalid}`);
  localStorage.setItem('nas-custom-commands', JSON.stringify([...new Set(commands)]));
  $('custom-commands').value = [...new Set(commands)].join('\n');
  updateCustomCount();
  $('command-profile-message').textContent = 'Custom commands saved in this browser. They will run after the automatic core profile.';
}
function updateCustomCount() {
  const count = getCustomCommands().length;
  if ($('custom-command-count')) $('custom-command-count').textContent = `${count} command${count === 1 ? '' : 's'}`;
}
function renderCoreProfile(name='catalyst') {
  $('core-command-list').textContent = CORE_PROFILES[name].map((cmd, i) => `${String(i+1).padStart(2,'0')}  ${cmd}`).join('\n');
  document.querySelectorAll('.profile-tab').forEach(button => button.classList.toggle('active', button.dataset.profile === name));
}
function showAppView(viewName) {
  ['collector','profiles','network-tools','history','r2o'].forEach(name => {
    $(`${name}-view`).classList.toggle('hidden', name !== viewName);
    const nav = $(`nav-${name}`); if (nav) nav.classList.toggle('active', name === viewName);
  });
  window.scrollTo({top: 0, behavior: 'smooth'});
}

$('nav-collector').addEventListener('click', () => showAppView('collector'));
$('nav-profiles').addEventListener('click', () => showAppView('profiles'));
$('nav-network-tools').addEventListener('click', () => showAppView('network-tools'));
$('nav-history').addEventListener('click', () => { showAppView('history'); loadHistory(); });
$('refresh-history').addEventListener('click', loadHistory);
$('nav-r2o').addEventListener('click', () => showAppView('r2o'));
document.querySelectorAll('.profile-tab').forEach(button => button.addEventListener('click', () => renderCoreProfile(button.dataset.profile)));
$('save-custom-commands').addEventListener('click', saveCustomCommands);
$('clear-custom-commands').addEventListener('click', () => { $('custom-commands').value=''; saveCustomCommands(); });
$('custom-commands').addEventListener('input', updateCustomCount);
$('export-profile').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify({name:'Custom Collection Commands',commands:getCustomCommands()}, null, 2)], {type:'application/json'});
  const url = URL.createObjectURL(blob); const link=document.createElement('a'); link.href=url; link.download='network-command-profile.json'; link.click(); URL.revokeObjectURL(url);
});
$('import-profile').addEventListener('change', async event => {
  try { const data=JSON.parse(await event.target.files[0].text()); $('custom-commands').value=(data.commands||[]).join('\n'); saveCustomCommands(); } catch { showError('The selected profile is not valid JSON.'); }
});
try { $('custom-commands').value = JSON.parse(localStorage.getItem('nas-custom-commands') || '[]').join('\n'); } catch {}
renderCoreProfile(); updateCustomCount(); renderDevices();

const storedJobId = localStorage.getItem(LAST_JOB_KEY);
if (storedJobId) restoreJob(storedJobId);

const networkTestState = { results: [] };

function parseNetworkTargets(raw) {
  return raw
    .split(/[\r\n,;]+/)
    .map(value => value.trim())
    .filter(Boolean);
}

function statusBadge(status) {
  const ok = status === 'SUCCESS';
  return `<span class="status-pill-small ${ok ? 'success' : 'failed'}">${ok ? 'Success' : 'Failed'}</span>`;
}

function renderNetworkResults(results) {
  networkTestState.results = results;
  $('network-total').textContent = results.length;
  $('network-ping-success').textContent = results.filter(row => row.ping_status === 'SUCCESS').length;
  $('network-dns-success').textContent = results.filter(row => row.dns_status === 'SUCCESS').length;
  $('network-results-body').innerHTML = results.map((row, position) => `
    <tr>
      <td>${position + 1}</td>
      <td>${escapeHtml(row.target)}</td>
      <td>${statusBadge(row.ping_status)}</td>
      <td>${row.latency_ms == null ? '—' : `${escapeHtml(row.latency_ms)} ms`}</td>
      <td>${escapeHtml(row.all_addresses || row.resolved_ip || '—')}</td>
      <td>${escapeHtml(row.reverse_dns || '—')}</td>
      <td>${statusBadge(row.dns_status)}</td>
      <td class="network-details">${escapeHtml(row.error || '—')}</td>
    </tr>`).join('');
  $('network-results-section').classList.remove('hidden');
}

$('run-network-tests').addEventListener('click', async () => {
  const targets = parseNetworkTargets($('network-targets').value);
  if (!targets.length) return showError('Enter at least one IP address or hostname.');
  if (targets.length > 1000) return showError('A maximum of 1,000 targets can be tested at once.');

  $('run-network-tests').disabled = true;
  $('network-test-progress').classList.remove('hidden');
  $('network-results-section').classList.add('hidden');
  try {
    const response = await fetch('/api/network-tests', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        targets,
        timeout_seconds: Number($('ping-timeout').value || 2),
      }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || 'Unable to run network tests');
    renderNetworkResults(payload.results || []);
  } catch (error) {
    showError(error.message);
  } finally {
    $('network-test-progress').classList.add('hidden');
    $('run-network-tests').disabled = false;
  }
});

$('clear-network-tests').addEventListener('click', () => {
  $('network-targets').value = '';
  $('network-results-body').innerHTML = '';
  $('network-results-section').classList.add('hidden');
  networkTestState.results = [];
});

function csvValue(value) {
  const text = String(value ?? '');
  return `"${text.replace(/"/g, '""')}"`;
}

$('export-network-csv').addEventListener('click', () => {
  if (!networkTestState.results.length) return showError('There are no network test results to export.');
  const headers = ['Input Order', 'Target', 'Ping Status', 'Latency ms', 'Resolved IP', 'All Addresses', 'Reverse DNS', 'DNS Status', 'Details'];
  const rows = networkTestState.results.map((row, index) => [
    index + 1,
    row.target,
    row.ping_status,
    row.latency_ms ?? '',
    row.resolved_ip,
    row.all_addresses,
    row.reverse_dns,
    row.dns_status,
    row.error,
  ]);
  const csv = [headers, ...rows].map(row => row.map(csvValue).join(',')).join('\r\n');
  const blob = new Blob([csv], {type: 'text/csv;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `ping-dns-results-${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
});

$('r2o-run').addEventListener('click', async () => {
  const fileInputs = {
    sitebook: $('r2o-file-sitebook'), lld: $('r2o-file-lld'), cmdb: $('r2o-file-cmdb'),
    network_diagram: $('r2o-file-network-diagram'), rack_elevations: $('r2o-file-rack-elevations'),
  };
  const form = new FormData();
  form.append('site_label', $('r2o-site-label').value.trim() || 'R2O Check');
  let anyFile = false;
  Object.entries(fileInputs).forEach(([key, input]) => {
    if (input.files && input.files[0]) { form.append(key, input.files[0]); anyFile = true; }
  });
  $('r2o-error').classList.add('hidden');
  if (!anyFile) {
    $('r2o-error').textContent = 'Upload at least one document.';
    $('r2o-error').classList.remove('hidden');
    return;
  }
  $('r2o-run').disabled = true;
  $('r2o-run').textContent = 'Running check…';
  try {
    const response = await fetch('/api/r2o-check', { method: 'POST', body: form });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || 'R2O check failed');
    renderR2oResults(payload);
  } catch (error) {
    $('r2o-error').textContent = error.message;
    $('r2o-error').classList.remove('hidden');
  } finally {
    $('r2o-run').disabled = false;
    $('r2o-run').textContent = 'Run R2O Check';
  }
});

function renderR2oResults(payload) {
  $('r2o-results').classList.remove('hidden');
  $('r2o-results-title').textContent = `Findings - ${payload.site_label}`;
  $('r2o-download').href = `/api/r2o-check/${payload.check_id}/download`;
  $('r2o-conflict-count').textContent = payload.summary.conflict_count;
  $('r2o-gap-count').textContent = payload.summary.coverage_gap_count;
  $('r2o-decomm-count').textContent = payload.summary.decommissioned_count;

  const groups = payload.summary.systematic_groups || [];
  if (groups.length) {
    $('r2o-systematic').classList.remove('hidden');
    $('r2o-systematic').innerHTML = '<strong>Systematic gaps - likely worth checking first</strong>' +
      groups.map(g => `<span>${g.count} devices starting with '${escapeHtml(g.prefix)}' exist in other documents but do not appear in the Sitebook at all.</span>`).join('');
  } else {
    $('r2o-systematic').classList.add('hidden');
  }

  const structural = payload.summary.structural_gaps || [];
  if (structural.length) {
    $('r2o-structural').classList.remove('hidden');
    $('r2o-structural').innerHTML = '<strong>Structural gaps</strong> (a field the Sitebook doesn\'t capture for this device category - not per-device errors)<br>' +
      structural.map(s => `${escapeHtml(s.source)}: '${escapeHtml(s.field)}' is populated for ${s.gap_count} of ${s.overlap} matching devices, but the Sitebook has none of them.`).join('<br>');
  } else {
    $('r2o-structural').classList.add('hidden');
  }

  const conflicts = payload.conflicts || [];
  $('r2o-conflicts-empty').classList.toggle('hidden', conflicts.length > 0);
  $('r2o-conflicts-body').innerHTML = conflicts.map(c => `<tr>
    <td>${escapeHtml(c.hostname)}</td><td>${escapeHtml(c.field)}</td><td>${escapeHtml(c.sitebook_value)}</td>
    <td>${escapeHtml(c.source)}</td><td>${escapeHtml(c.other_value)}</td>
  </tr>`).join('');

  const gaps = payload.coverage_gaps || [];
  $('r2o-gaps-empty').classList.toggle('hidden', gaps.length > 0);
  $('r2o-gaps-body').innerHTML = gaps.map(g => `<tr>
    <td>${escapeHtml(g.hostname)}</td><td>${escapeHtml((g.present_in || []).join(', '))}</td>
  </tr>`).join('');

  $('r2o-results').scrollIntoView({behavior: 'smooth', block: 'start'});
}