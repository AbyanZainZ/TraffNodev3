let currentStatusData = null;
let pollTimer = null;
let activeFilter = 'all';
let currentLogNodeId = null;

const valServerIp = document.getElementById('val-server-ip');
const daemonStatusText = document.getElementById('daemon-status-text');
const statRelayPorts = document.getElementById('stat-relay-ports');
const statRelayDetail = document.getElementById('stat-relay-detail');
const statHarvesterWorkers = document.getElementById('stat-harvester-workers');
const statHarvesterDetail = document.getElementById('stat-harvester-detail');
const statBandwidthTotal = document.getElementById('stat-bandwidth-total');
const statBandwidthSpeed = document.getElementById('stat-bandwidth-speed');
const statCpuRam = document.getElementById('stat-cpu-ram');
const statRamDetail = document.getElementById('stat-ram-detail');
const lblBtnTotalAll = document.getElementById('lbl-btn-total-all');

const cfgToken = document.getElementById('cfg-token');
const btnSaveToken = document.getElementById('btn-save-token');

const cfgSurfsharkKey = document.getElementById('cfg-surfshark-key');
const cfgSurfsharkRegion = document.getElementById('cfg-surfshark-region');
const cfgSurfsharkCount = document.getElementById('cfg-surfshark-count');
const btnGenerateSs = document.getElementById('btn-generate-ss');
const btnClearSs = document.getElementById('btn-clear-ss');

const proxiesTextarea = document.getElementById('proxies-textarea');
const lblProxyCountHint = document.getElementById('lbl-proxy-count-hint');
const btnSaveProxies = document.getElementById('btn-save-proxies');
const btnCheckProxies = document.getElementById('btn-check-proxies');
const btnClearProxies = document.getElementById('btn-clear-proxies');

const cfgRelayPort = document.getElementById('cfg-relay-port');
const cfgRelayUser = document.getElementById('cfg-relay-user');
const cfgRelayPass = document.getElementById('cfg-relay-pass');
const btnSaveRelayCfg = document.getElementById('btn-save-relay-cfg');
const btnStartRelayActive = document.getElementById('btn-start-relay-active');
const btnStopRelayActive = document.getElementById('btn-stop-relay-active');

const btnStartHybrid = document.getElementById('btn-start-hybrid');
const btnStartHarvesterOnly = document.getElementById('btn-start-harvester-only');
const btnStartRelayOnly = document.getElementById('btn-start-relay-only');
const btnStopAll = document.getElementById('btn-stop-all');
const btnPurgeError = document.getElementById('btn-purge-error');
const cntPurgeError = document.getElementById('cnt-purge-error');
const btnExportRelay = document.getElementById('btn-export-relay');
const btnExportProxies = document.getElementById('btn-export-proxies');
const btnExportConfig = document.getElementById('btn-export-config');

const tableFilter = document.getElementById('table-filter');
const nodesTbody = document.getElementById('nodes-tbody');
const toastEl = document.getElementById('tn-toast');

const cntPillAll = document.getElementById('cnt-pill-all');
const cntPillSs = document.getElementById('cnt-pill-ss');
const cntPillPx = document.getElementById('cnt-pill-px');
const cntPillRelay = document.getElementById('cnt-pill-relay');
const cntPillHarvester = document.getElementById('cnt-pill-harvester');
const cntPillError = document.getElementById('cnt-pill-error');

const logModal = document.getElementById('log-modal');
const logModalTitle = document.getElementById('log-modal-title');
const logModalBody = document.getElementById('log-modal-body');
const btnCloseModal = document.getElementById('btn-close-modal');
const btnRefreshLog = document.getElementById('btn-refresh-log');

function showToast(message, isError = false) {
    if (!toastEl) return;
    toastEl.textContent = message;
    toastEl.style.display = 'block';
    toastEl.style.borderColor = isError ? 'var(--danger)' : 'var(--primary)';
    toastEl.style.color = isError ? '#ff5252' : '#ffffff';

    setTimeout(() => {
        toastEl.style.display = 'none';
    }, 3800);
}

function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let val = bytes;
    for (const unit of units) {
        if (val < 1024) return `${val.toFixed(2)} ${unit}`;
        val /= 1024;
    }
    return `${val.toFixed(2)} PB`;
}

function formatUptime(seconds) {
    if (!seconds || seconds <= 0) return '0s';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
}

function updateProxyLineCount() {
    if (!proxiesTextarea || !lblProxyCountHint) return;
    const lines = proxiesTextarea.value.split('\n').filter(l => l.trim().length > 0 && !l.trim().startsWith('#'));
    lblProxyCountHint.textContent = `${lines.length} baris proxy terdeteksi`;
}

if (proxiesTextarea) {
    proxiesTextarea.addEventListener('input', updateProxyLineCount);
}

async function fetchStatus() {
    try {
        const res = await fetch('/api/status');
        if (!res.ok) return;
        const data = await res.json();
        currentStatusData = data;
        renderDashboard(data);
    } catch (err) {
        console.error("Fetch status error:", err);
    }
}

async function fetchRawProxies() {
    try {
        const res = await fetch('/api/proxies/raw');
        if (res.ok && proxiesTextarea && proxiesTextarea.value === "") {
            const txt = await res.text();
            proxiesTextarea.value = txt;
            updateProxyLineCount();
        }
    } catch (e) {}
}

function renderDashboard(data) {
    if (valServerIp) valServerIp.textContent = data.server_ip || '127.0.0.1';

    const cfg = data.config || {};
    if (cfgToken && document.activeElement !== cfgToken && cfg.traff_token) {
        cfgToken.value = cfg.traff_token;
    }
    if (cfgSurfsharkKey && document.activeElement !== cfgSurfsharkKey && cfg.surfshark_private_key) {
        cfgSurfsharkKey.value = cfg.surfshark_private_key;
    }
    if (cfgSurfsharkRegion && document.activeElement !== cfgSurfsharkRegion && cfg.surfshark_region) {
        cfgSurfsharkRegion.value = cfg.surfshark_region;
    }
    if (cfgSurfsharkCount && document.activeElement !== cfgSurfsharkCount && cfg.surfshark_node_count) {
        cfgSurfsharkCount.value = cfg.surfshark_node_count;
    }
    if (cfgRelayPort && document.activeElement !== cfgRelayPort && cfg.relay_start_port) {
        cfgRelayPort.value = cfg.relay_start_port;
    }
    if (cfgRelayUser && document.activeElement !== cfgRelayUser && cfg.relay_client_user) {
        cfgRelayUser.value = cfg.relay_client_user;
    }
    if (cfgRelayPass && document.activeElement !== cfgRelayPass && cfg.relay_client_pass) {
        cfgRelayPass.value = cfg.relay_client_pass;
    }

    const m = data.metrics || {};
    const total = m.total_nodes || 0;
    const hRunning = m.harvester_running || 0;
    const rRunning = m.relay_running || 0;
    const ssTotal = m.surfshark_total || 0;
    const pxTotal = m.proxy_total || 0;

    if (statRelayPorts) statRelayPorts.textContent = rRunning;
    if (statRelayDetail) statRelayDetail.textContent = `${m.relay_active_conns || 0} Active Conns (${m.relay_traffic_in || '0 B'} in, ${m.relay_traffic_out || '0 B'} out)`;

    if (statHarvesterWorkers) statHarvesterWorkers.textContent = hRunning;
    if (statHarvesterDetail) statHarvesterDetail.textContent = `${total} Total Nodes (SS: ${ssTotal}, PX: ${pxTotal})`;

    const bw = m.bandwidth || {};
    if (statBandwidthTotal) {
        statBandwidthTotal.textContent = `${bw.formatted_in || '0 B'} ↓ / ${bw.formatted_out || '0 B'} ↑`;
    }
    if (statBandwidthSpeed) {
        statBandwidthSpeed.textContent = `${formatBytes(bw.speed_up_bps || 0)}/s Up, ${formatBytes(bw.speed_down_bps || 0)}/s Down`;
    }

    const sys = data.system || {};
    if (statCpuRam) statCpuRam.textContent = `${sys.cpu_percent || 0}% CPU`;
    if (statRamDetail) statRamDetail.textContent = `RAM: ${sys.ram_used_mb || 0} MB / ${sys.ram_total_mb || 0} MB (${sys.ram_percent || 0}%)`;

    if (lblBtnTotalAll) lblBtnTotalAll.textContent = total;

    const allNodesList = data.nodes || [];
    const deadCount = allNodesList.filter(n => n.status === 'ERROR' || n.is_alive === false).length;

    if (cntPillAll) cntPillAll.textContent = allNodesList.length;
    if (cntPillSs) cntPillSs.textContent = ssTotal;
    if (cntPillPx) cntPillPx.textContent = pxTotal;
    if (cntPillRelay) cntPillRelay.textContent = rRunning;
    if (cntPillHarvester) cntPillHarvester.textContent = hRunning;
    if (cntPillError) cntPillError.textContent = deadCount;
    if (cntPurgeError) cntPurgeError.textContent = deadCount;

    renderTable(allNodesList);
}

function renderTable(nodesList) {
    if (!nodesTbody) return;

    const searchTerm = (tableFilter ? tableFilter.value.trim().toLowerCase() : '');

    const filtered = nodesList.filter(n => {
        if (activeFilter === 'surfshark' && n.node_type !== 'surfshark') return false;
        if (activeFilter === 'proxy' && n.node_type !== 'proxy') return false;
        if (activeFilter === 'relay_running' && n.relay_status !== 'RUNNING') return false;
        if (activeFilter === 'harvester_running' && n.status !== 'RUNNING' && n.status !== 'STARTING') return false;
        if (activeFilter === 'error' && (n.status !== 'ERROR' && n.is_alive !== false)) return false;

        if (searchTerm) {
            const idStr = String(n.id);
            const dev = (n.device_name || '').toLowerCase();
            const host = (n.host || '').toLowerCase();
            const country = (n.country || '').toLowerCase();
            const endpoint = (n.endpoint || '').toLowerCase();
            const type = (n.node_type || '').toLowerCase();
            const status = (n.status || '').toLowerCase();

            if (!idStr.includes(searchTerm) &&
                !dev.includes(searchTerm) &&
                !host.includes(searchTerm) &&
                !country.includes(searchTerm) &&
                !endpoint.includes(searchTerm) &&
                !type.includes(searchTerm) &&
                !status.includes(searchTerm)) {
                return false;
            }
        }
        return true;
    });

    if (filtered.length === 0) {
        nodesTbody.innerHTML = `
            <tr>
                <td colspan="10" style="text-align: center; color: var(--text-muted); padding: 30px;">
                    Tidak ada worker yang sesuai dengan filter '${activeFilter.toUpperCase()}'.
                </td>
            </tr>
        `;
        return;
    }

    let html = '';
    const serverIp = (currentStatusData ? currentStatusData.server_ip : '127.0.0.1') || '127.0.0.1';

    for (const node of filtered) {
        const isSS = (node.node_type === 'surfshark');
        const typeBadge = isSS
            ? `<span class="tn-badge tn-badge-surfshark">🦈 SURFSHARK</span>`
            : `<span class="tn-badge tn-badge-proxy">🌐 PROXY</span>`;

        let hBadge = `<span class="tn-badge tn-badge-idle">IDLE</span>`;
        if (node.status === 'RUNNING') {
            hBadge = `<span class="tn-badge tn-badge-running">● RUNNING</span>`;
        } else if (node.status === 'STARTING') {
            hBadge = `<span class="tn-badge tn-badge-starting">⏳ STARTING</span>`;
        } else if (node.status === 'STOPPED') {
            hBadge = `<span class="tn-badge tn-badge-stopped">■ STOPPED</span>`;
        } else if (node.status === 'ERROR') {
            hBadge = `<span class="tn-badge tn-badge-error" title="${node.error || 'Error'}">✖ ERROR</span>`;
        }

        let rBadge = `<span class="tn-badge tn-badge-stopped">CLOSED</span>`;
        if (node.relay_status === 'RUNNING') {
            rBadge = `<span class="tn-badge tn-badge-running">⚡ OPEN</span>`;
        } else if (node.relay_status === 'ERROR') {
            rBadge = `<span class="tn-badge tn-badge-error">✖ FAILED</span>`;
        }

        const upstreamText = isSS
            ? (node.endpoint || 'WireGuard')
            : (node.host ? `${node.host}:${node.port}` : '-');

        const relayPortText = node.relay_port
            ? `<span style="color: var(--primary); font-weight: 700;">:${node.relay_port}</span>`
            : `<span style="color: var(--text-sub);">-</span>`;

        const trafficText = `${formatBytes(node.bytes_in || 0)} / ${formatBytes(node.bytes_out || 0)}`;
        const uptimeText = formatUptime(node.uptime_seconds);

        const isHRunning = (node.status === 'RUNNING' || node.status === 'STARTING');
        const hBtn = isHRunning
            ? `<button type="button" class="tn-btn-action" onclick="stopHarvester(${node.id})">Stop Harvester</button>`
            : `<button type="button" class="tn-btn-action" onclick="startHarvester(${node.id})">Start Harvester</button>`;

        const isRRunning = (node.relay_status === 'RUNNING');
        const rBtn = isRRunning
            ? `<button type="button" class="tn-btn-action" style="border-color: #00e5ff; color: #00e5ff;" onclick="stopRelay(${node.id})">Tutup Port</button>`
            : `<button type="button" class="tn-btn-action" style="border-color: #00e5ff; color: #00e5ff;" onclick="startRelay(${node.id})">Buka Port</button>`;

        html += `
            <tr>
                <td><strong>#${node.id}</strong></td>
                <td>${typeBadge}</td>
                <td style="color: #ffffff;">${node.device_name || `Node-${node.id}`}</td>
                <td style="color: var(--text-muted);">${upstreamText}</td>
                <td>${relayPortText}</td>
                <td>${hBadge}</td>
                <td>${rBadge}</td>
                <td>${trafficText}</td>
                <td>${uptimeText}</td>
                <td style="text-align: right; white-space: nowrap;">
                    ${hBtn}
                    ${rBtn}
                    <button type="button" class="tn-btn-action" onclick="viewNodeLog(${node.id})">Log</button>
                    <button type="button" class="tn-btn-action" onclick="deleteNode(${node.id})" title="Hapus node #${node.id}" style="color: #ff5252; margin-left: 4px;">🗑️</button>
                </td>
            </tr>
        `;
    }
    nodesTbody.innerHTML = html;
}

window.setTableFilter = function(filterName, btnEl) {
    document.querySelectorAll('.tn-pill').forEach(b => b.classList.remove('active'));
    if (btnEl) {
        btnEl.classList.add('active');
    } else {
        const target = document.querySelector(`[data-filter="${filterName}"]`);
        if (target) target.classList.add('active');
    }
    activeFilter = filterName || 'all';
    if (currentStatusData && currentStatusData.nodes) {
        renderTable(currentStatusData.nodes);
    }
};

if (tableFilter) {
    tableFilter.addEventListener('input', () => {
        if (currentStatusData && currentStatusData.nodes) {
            renderTable(currentStatusData.nodes);
        }
    });
}

// Config Token
if (btnSaveToken) {
    btnSaveToken.addEventListener('click', async () => {
        const token = (cfgToken.value || '').trim();
        if (!token) {
            showToast("Token TraffMonetizer tidak boleh kosong.", true);
            return;
        }
        btnSaveToken.disabled = true;
        try {
            const res = await fetch('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ traff_token: token })
            });
            const data = await res.json();
            if (data.success) {
                showToast("Token TraffMonetizer berhasil disimpan.");
                fetchStatus();
            } else {
                showToast(data.message || "Gagal menyimpan token.", true);
            }
        } catch (e) {
            showToast("Koneksi gagal saat menyimpan token.", true);
        } finally {
            btnSaveToken.disabled = false;
        }
    });
}

// Config Relay
if (btnSaveRelayCfg) {
    btnSaveRelayCfg.addEventListener('click', async () => {
        const port = parseInt(cfgRelayPort.value) || 10001;
        const user = (cfgRelayUser.value || '').trim();
        const pass = (cfgRelayPass.value || '').trim();

        btnSaveRelayCfg.disabled = true;
        try {
            const res = await fetch('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    traff_token: cfgToken.value || '',
                    relay_start_port: port,
                    relay_client_user: user,
                    relay_client_pass: pass
                })
            });
            const data = await res.json();
            if (data.success) {
                showToast("Pengaturan Relay Gateway berhasil disimpan.");
                fetchStatus();
            } else {
                showToast(data.message || "Gagal menyimpan relay.", true);
            }
        } catch (e) {
            showToast("Koneksi gagal.", true);
        } finally {
            btnSaveRelayCfg.disabled = false;
        }
    });
}

// Generate Surfshark
if (btnGenerateSs) {
    btnGenerateSs.addEventListener('click', async () => {
        const privkey = (cfgSurfsharkKey.value || '').trim();
        if (!privkey) {
            showToast("WireGuard Private Key Surfshark harus diisi terlebih dahulu.", true);
            return;
        }
        btnGenerateSs.disabled = true;
        try {
            await fetch('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    traff_token: cfgToken.value || '',
                    surfshark_private_key: privkey,
                    surfshark_region: cfgSurfsharkRegion.value,
                    surfshark_node_count: parseInt(cfgSurfsharkCount.value) || 50
                })
            });

            const res = await fetch('/api/surfshark/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    region: cfgSurfsharkRegion.value,
                    count: parseInt(cfgSurfsharkCount.value) || 50,
                    mode: "replace"
                })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                fetchStatus();
            } else {
                showToast(data.detail || "Gagal generate Surfshark.", true);
            }
        } catch (e) {
            showToast("Koneksi gagal saat generate Surfshark.", true);
        } finally {
            btnGenerateSs.disabled = false;
        }
    });
}

// Clear Surfshark
if (btnClearSs) {
    btnClearSs.addEventListener('click', async () => {
        if (!confirm("Hapus seluruh node Surfshark dari pool?")) return;
        try {
            const res = await fetch('/api/nodes/surfshark', { method: 'DELETE' });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                fetchStatus();
            }
        } catch (e) {
            showToast("Gagal mereset Surfshark.", true);
        }
    });
}

// Save Proxies
if (btnSaveProxies) {
    btnSaveProxies.addEventListener('click', async () => {
        const text = (proxiesTextarea.value || '').trim();
        if (!text) {
            showToast("Textarea proxy masih kosong.", true);
            return;
        }
        btnSaveProxies.disabled = true;
        try {
            const res = await fetch('/api/proxies', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ raw_text: text, mode: "replace" })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                fetchStatus();
            }
        } catch (e) {
            showToast("Gagal menyimpan proxy.", true);
        } finally {
            btnSaveProxies.disabled = false;
        }
    });
}

// Test Proxies
if (btnCheckProxies) {
    btnCheckProxies.addEventListener('click', async () => {
        try {
            const res = await fetch('/api/check', { method: 'POST' });
            const data = await res.json();
            showToast(data.message);
        } catch (e) {
            showToast("Gagal memulai test proxy.", true);
        }
    });
}

// Clear Proxies
if (btnClearProxies) {
    btnClearProxies.addEventListener('click', async () => {
        if (!confirm("Hapus seluruh Custom Proxy dari pool?")) return;
        try {
            const res = await fetch('/api/nodes/proxies', { method: 'DELETE' });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                if (proxiesTextarea) proxiesTextarea.value = '';
                updateProxyLineCount();
                fetchStatus();
            }
        } catch (e) {
            showToast("Gagal mereset proxy.", true);
        }
    });
}

// Master Controls
if (btnStartHybrid) {
    btnStartHybrid.addEventListener('click', async () => {
        btnStartHybrid.disabled = true;
        try {
            const res = await fetch('/api/hybrid/start-all', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                fetchStatus();
            } else {
                showToast(data.detail || "Gagal memulai mode hybrid.", true);
            }
        } catch (e) {
            showToast("Koneksi gagal.", true);
        } finally {
            btnStartHybrid.disabled = false;
        }
    });
}

if (btnStartHarvesterOnly) {
    btnStartHarvesterOnly.addEventListener('click', async () => {
        btnStartHarvesterOnly.disabled = true;
        try {
            const res = await fetch('/api/harvester/start-all', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                fetchStatus();
            } else {
                showToast(data.detail || "Gagal memulai harvester.", true);
            }
        } catch (e) {
            showToast("Koneksi gagal.", true);
        } finally {
            btnStartHarvesterOnly.disabled = false;
        }
    });
}

if (btnStartRelayOnly || btnStartRelayActive) {
    const handler = async () => {
        try {
            const res = await fetch('/api/relay/start-all', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                fetchStatus();
            } else {
                showToast(data.detail || "Gagal membuka port relay.", true);
            }
        } catch (e) {
            showToast("Koneksi gagal.", true);
        }
    };
    if (btnStartRelayOnly) btnStartRelayOnly.addEventListener('click', handler);
    if (btnStartRelayActive) btnStartRelayActive.addEventListener('click', handler);
}

if (btnStopAll) {
    btnStopAll.addEventListener('click', async () => {
        btnStopAll.disabled = true;
        try {
            const res = await fetch('/api/hybrid/stop-all', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                fetchStatus();
            }
        } catch (e) {
            showToast("Koneksi gagal saat stop all.", true);
        } finally {
            btnStopAll.disabled = false;
        }
    });
}

if (btnStopRelayActive) {
    btnStopRelayActive.addEventListener('click', async () => {
        try {
            const res = await fetch('/api/relay/stop-all', { method: 'POST' });
            const data = await res.json();
            showToast(data.message);
            fetchStatus();
        } catch (e) {
            showToast("Gagal menutup port relay.", true);
        }
    });
}

// Purge Error Nodes
if (btnPurgeError) {
    btnPurgeError.addEventListener('click', async () => {
        if (!confirm("Hapus semua node yang berstatus ERROR atau offline?")) return;
        btnPurgeError.disabled = true;
        try {
            const res = await fetch('/api/nodes/error', { method: 'DELETE' });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                fetchStatus();
            } else {
                showToast(data.message || "Gagal membersihkan error.", true);
            }
        } catch (e) {
            showToast("Koneksi gagal.", true);
        } finally {
            btnPurgeError.disabled = false;
        }
    });
}

// Exports
if (btnExportRelay) {
    btnExportRelay.addEventListener('click', () => {
        window.open('/api/export/relay-client', '_blank');
    });
}

if (btnExportProxies) {
    btnExportProxies.addEventListener('click', () => {
        window.open('/api/export/live-proxies', '_blank');
    });
}

if (btnExportConfig) {
    btnExportConfig.addEventListener('click', () => {
        window.open('/api/export/live-config', '_blank');
    });
}

// Individual Node Operations
window.startHarvester = async function(nodeId) {
    try {
        const res = await fetch(`/api/node/${nodeId}/start-harvester`, { method: 'POST' });
        const data = await res.json();
        if (res.ok && data.success) {
            showToast(`Harvester #${nodeId} dijalankan.`);
            fetchStatus();
        } else {
            showToast(data.detail || "Gagal start harvester.", true);
        }
    } catch (e) {
        showToast("Koneksi gagal.", true);
    }
};

window.stopHarvester = async function(nodeId) {
    try {
        const res = await fetch(`/api/node/${nodeId}/stop-harvester`, { method: 'POST' });
        const data = await res.json();
        if (res.ok && data.success) {
            showToast(`Harvester #${nodeId} dihentikan.`);
            fetchStatus();
        }
    } catch (e) {
        showToast("Koneksi gagal.", true);
    }
};

window.startRelay = async function(nodeId) {
    try {
        const res = await fetch(`/api/node/${nodeId}/start-relay`, { method: 'POST' });
        const data = await res.json();
        if (res.ok && data.success) {
            showToast(`Port relay :${data.port} untuk node #${nodeId} dibuka.`);
            fetchStatus();
        } else {
            showToast(data.detail || "Gagal membuka relay.", true);
        }
    } catch (e) {
        showToast("Koneksi gagal.", true);
    }
};

window.stopRelay = async function(nodeId) {
    try {
        const res = await fetch(`/api/node/${nodeId}/stop-relay`, { method: 'POST' });
        const data = await res.json();
        if (res.ok && data.success) {
            showToast(`Port relay node #${nodeId} ditutup.`);
            fetchStatus();
        }
    } catch (e) {
        showToast("Koneksi gagal.", true);
    }
};

window.deleteNode = async function(nodeId) {
    if (!confirm(`Hapus node #${nodeId}?`)) return;
    try {
        const res = await fetch(`/api/node/${nodeId}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            showToast(data.message);
            fetchStatus();
        } else {
            showToast(data.message || "Gagal menghapus node.", true);
        }
    } catch (e) {
        showToast("Koneksi gagal.", true);
    }
};

// Log Modal
window.viewNodeLog = async function(nodeId) {
    currentLogNodeId = nodeId;
    if (logModalTitle) logModalTitle.textContent = `Worker Log: Node #${nodeId}`;
    if (logModalBody) logModalBody.textContent = "Mengambil log worker...";
    if (logModal) logModal.style.display = 'block';

    try {
        const res = await fetch(`/api/node/${nodeId}/logs`);
        const text = await res.text();
        if (logModalBody) logModalBody.textContent = text || "Belum ada log tercatat.";
    } catch (e) {
        if (logModalBody) logModalBody.textContent = "Gagal mengambil log dari server.";
    }
};

if (btnCloseModal) {
    btnCloseModal.addEventListener('click', () => {
        if (logModal) logModal.style.display = 'none';
        currentLogNodeId = null;
    });
}

if (btnRefreshLog) {
    btnRefreshLog.addEventListener('click', () => {
        if (currentLogNodeId !== null) {
            window.viewNodeLog(currentLogNodeId);
        }
    });
}

window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && logModal && logModal.style.display === 'block') {
        logModal.style.display = 'none';
        currentLogNodeId = null;
    }
});

window.addEventListener('click', (e) => {
    if (e.target === logModal) {
        logModal.style.display = 'none';
        currentLogNodeId = null;
    }
});

// Initial Bootstrap
document.addEventListener('DOMContentLoaded', () => {
    fetchStatus();
    fetchRawProxies();
    pollTimer = setInterval(fetchStatus, 4000);
});
