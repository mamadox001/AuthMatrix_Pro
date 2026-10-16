/**
 * AuthMatrix — Security Suite Professional Edition
 * Complete client-side application logic for HTTP debugging proxy & RBAC contract verification.
 */
const App = (() => {
    'use strict';

    const API_BASE = '';
    let wsConnection = null;
    let interceptEnabled = false;
    let trafficLogs = [];
    let roles = [];
    let policies = [];
    let matrixResults = null;
    let repeaterTabs = [
        { id: 0, name: 'Request 1', method: 'GET', url: 'http://localhost:3000/api/users', headers: [{ name: 'Accept', value: 'application/json' }], body: '', response: null }
    ];
    let activeRepeaterTab = 0;
    let selectedHistoryRow = -1;
    let activeFinding = null;
    const startTime = Date.now();

    /* ============================================================
       INITIALIZATION
       ============================================================ */

    function init() {
        connectWebSocket();
        loadConfig();
        refreshRoles();
        refreshPolicies();
        refreshHistory();
        startStatusUpdater();
        setupKeyboardShortcuts();
        initDecoderListeners();

        // Initialize target URL from input
        const targetUrl = document.getElementById('target-url-input').value;
        const sitemapHost = document.getElementById('sitemap-host-label');
        if (sitemapHost) sitemapHost.textContent = targetUrl;

        setStatus('AuthMatrix Security Suite Pro initialized. Ready.');
    }

    async function loadConfig() {
        try {
            const data = await api('GET', '/api/config');
            if (data && data.targetHost) {
                document.getElementById('target-url-input').value = data.targetHost;
                document.getElementById('setting-target-url').value = data.targetHost;
                const sitemapHost = document.getElementById('sitemap-host-label');
                if (sitemapHost) sitemapHost.textContent = data.targetHost;
            }
            if (data && data.proxyPort) {
                document.getElementById('setting-proxy-port').value = data.proxyPort;
                const proxyText = document.getElementById('proxy-status-text');
                if (proxyText) proxyText.textContent = `Proxy: :${data.proxyPort}`;
            }
        } catch (e) {
            console.warn('Failed to load initial config:', e);
        }
    }

    /* ============================================================
       API CLIENT
       ============================================================ */

    async function api(method, path, body) {
        const opts = {
            method,
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }
        };
        if (body !== undefined && body !== null) {
            opts.body = JSON.stringify(body);
        }
        try {
            const res = await fetch(API_BASE + path, opts);
            const text = await res.text();
            let data;
            try { data = JSON.parse(text); } catch { data = text; }
            if (!res.ok) {
                throw new Error(typeof data === 'object' && (data.error || data.message) ? (data.error || data.message) : `HTTP ${res.status}: ${text}`);
            }
            return data;
        } catch (err) {
            if (err.message && err.message.includes('Failed to fetch')) {
                throw new Error('Connection refused. Backend server unreachable.');
            }
            throw err;
        }
    }

    /* ============================================================
       WEBSOCKET LIVE STREAMING
       ============================================================ */

    function connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/traffic`;

        try {
            wsConnection = new WebSocket(wsUrl);

            wsConnection.onopen = () => {
                updateWsStatus(true);
                setStatus('WebSocket connected. Streaming live HTTP traffic.');
            };

            wsConnection.onmessage = (event) => {
                try {
                    const log = JSON.parse(event.data);
                    handleNewTrafficLog(log);
                } catch (e) {
                    console.warn('Invalid WS message payload:', e);
                }
            };

            wsConnection.onclose = () => {
                updateWsStatus(false);
                setTimeout(connectWebSocket, 4000);
            };

            wsConnection.onerror = () => {
                updateWsStatus(false);
            };
        } catch (e) {
            updateWsStatus(false);
        }
    }

    function updateWsStatus(connected) {
        const el = document.getElementById('ws-status');
        if (!el) return;
        const dot = el.querySelector('.dot');
        const text = el.querySelector('span:last-child');
        if (connected) {
            dot.className = 'dot dot-active';
            text.textContent = 'WS: Connected';
        } else {
            dot.className = 'dot dot-inactive';
            text.textContent = 'WS: Disconnected';
        }
    }

    function handleNewTrafficLog(log) {
        trafficLogs.unshift(log);
        if (trafficLogs.length > 2000) trafficLogs.pop();
        updateHistoryTable();
        updateDashboardStats();
        addActivityItem(log);
        updateTargetSiteMap();
    }

    /* ============================================================
       TAB NAVIGATION
       ============================================================ */

    function switchTab(tabName) {
        document.querySelectorAll('#main-tabs .tab').forEach(t => {
            t.classList.toggle('active', t.dataset.tab === tabName);
        });
        document.querySelectorAll('.tab-panel').forEach(p => {
            p.classList.toggle('active', p.id === `panel-${tabName}`);
        });

        if (tabName === 'history') refreshHistory();
        if (tabName === 'target') updateTargetSiteMap();
        if (tabName === 'roles') refreshRoles();
        if (tabName === 'policies') refreshPolicies();
    }

    /* ============================================================
       TARGET & SITEMAP
       ============================================================ */

    function updateTargetSiteMap() {
        const treeContainer = document.getElementById('sitemap-endpoints-tree');
        const tbody = document.getElementById('target-endpoints-tbody');
        if (!treeContainer || !tbody) return;

        const endpointsMap = {};
        trafficLogs.forEach(log => {
            const path = log.path || '/';
            const method = log.method || 'GET';
            const status = log.response_status || log.responseStatus || 0;
            const key = `${method} ${path}`;

            if (!endpointsMap[key]) {
                endpointsMap[key] = { path, method, count: 1, lastStatus: status, rawLog: log };
            } else {
                endpointsMap[key].count++;
                endpointsMap[key].lastStatus = status;
            }
        });

        const list = Object.values(endpointsMap);
        document.getElementById('target-count-badge').textContent = `${list.length} endpoints discovered`;

        // Render Tree
        const paths = [...new Set(list.map(e => e.path))].sort();
        treeContainer.innerHTML = paths.map(p => `
            <div class="tree-node" onclick="App.filterHistoryByPath('${escHtml(p)}')">
                <span class="tree-icon">📄</span>
                <span>${escHtml(p)}</span>
            </div>
        `).join('');

        // Render Table
        if (list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--text-tertiary)">
                No endpoints discovered yet. Pass HTTP traffic through reverse proxy on port 8080.
            </td></tr>`;
            return;
        }

        tbody.innerHTML = list.map(item => `
            <tr>
                <td><span class="activity-method method-${item.method.toLowerCase()}">${escHtml(item.method)}</span></td>
                <td><code>${escHtml(item.path)}</code></td>
                <td>${item.count}</td>
                <td><span class="badge ${item.lastStatus >= 200 && item.lastStatus < 300 ? 'badge-success' : item.lastStatus >= 400 ? 'badge-danger' : 'badge-warning'}">${item.lastStatus}</span></td>
                <td>
                    <button class="btn btn-xs btn-primary" onclick="App.sendTargetToRepeater('${escHtml(item.method)}', '${escHtml(item.path)}')">Repeater</button>
                    <button class="btn btn-xs btn-ghost" onclick="App.createPolicyFromTarget('${escHtml(item.method)}', '${escHtml(item.path)}')">+ Policy</button>
                </td>
            </tr>
        `).join('');
    }

    function refreshTargetSiteMap() {
        updateTargetSiteMap();
        toast('Target Site Map refreshed.', 'info');
    }

    function exportTargetSiteMap() {
        const uniquePaths = [...new Set(trafficLogs.map(l => `${l.method} ${l.path}`))].sort();
        const blob = new Blob([uniquePaths.join('\n')], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'authmatrix-target-scope.txt';
        a.click();
        URL.revokeObjectURL(url);
        toast('Target scope exported.', 'success');
    }

    function filterHistoryByPath(path) {
        switchTab('history');
        const filterInput = document.getElementById('history-filter');
        if (filterInput) {
            filterInput.value = path;
            filterHistory();
        }
    }

    function sendTargetToRepeater(method, path) {
        const targetUrl = document.getElementById('target-url-input').value.trim();
        const fullUrl = targetUrl + (path.startsWith('/') ? path : '/' + path);

        addRepeaterTab();
        document.getElementById('repeater-method').value = method;
        document.getElementById('repeater-url').value = fullUrl;
        repeaterTabs[activeRepeaterTab].method = method;
        repeaterTabs[activeRepeaterTab].url = fullUrl;
        switchTab('repeater');
        toast(`Endpoint ${method} ${path} sent to Repeater.`, 'success');
    }

    function createPolicyFromTarget(method, path) {
        showAddPolicyModal();
        document.getElementById('policy-name').value = `${method} ${path}`;
        document.getElementById('policy-method').value = method;
        document.getElementById('policy-path').value = path;
        document.getElementById('policy-expect').value = '{"admin": 200, "member_a": 200, "guest": 401}';
    }

    /* ============================================================
       PROXY & INTERCEPT
       ============================================================ */

    function toggleIntercept() {
        interceptEnabled = !interceptEnabled;
        const btn = document.getElementById('btn-intercept');
        if (interceptEnabled) {
            btn.classList.add('active');
            btn.innerHTML = '<span class="intercept-dot"></span> Intercept is ON';
            toast('Intercept enabled. Requests will be captured for inspection.', 'warning');
        } else {
            btn.classList.remove('active');
            btn.innerHTML = '<span class="intercept-dot"></span> Intercept is OFF';
            toast('Intercept disabled. Traffic flowing normally.', 'info');
        }

        const proxyDot = document.getElementById('proxy-status').querySelector('.dot');
        const proxyText = document.getElementById('proxy-status-text');
        if (interceptEnabled) {
            proxyDot.className = 'dot dot-warning';
            proxyText.textContent = 'Proxy: Intercepting';
        } else {
            proxyDot.className = 'dot dot-active';
            proxyText.textContent = 'Proxy: :8080';
        }
    }

    function forwardRequest() {
        toast('Intercepted request forwarded to target server.', 'info');
    }

    function dropRequest() {
        toast('Intercepted request dropped (connection closed).', 'warning');
    }

    function switchProxyPane(paneId) {
        const container = document.getElementById('proxy-request-pane');
        const tabs = ['raw-req', 'headers-req', 'params-req', 'hex-req'];
        container.querySelectorAll('.pane-tab').forEach((t, i) => {
            t.classList.toggle('active', tabs[i] === paneId);
        });
        container.querySelectorAll('.pane-panel').forEach(p => {
            p.classList.toggle('active', p.id === `pane-${paneId}`);
        });
    }

    function switchProxyRespPane(paneId) {
        const container = document.getElementById('proxy-response-pane');
        const tabs = ['raw-resp', 'headers-resp', 'pretty-resp', 'hex-resp'];
        container.querySelectorAll('.pane-tab').forEach((t, i) => {
            t.classList.toggle('active', tabs[i] === paneId);
        });
        container.querySelectorAll('.pane-panel').forEach(p => {
            p.classList.toggle('active', p.id === `pane-${paneId}`);
        });
    }

    function sendToRepeater() {
        const raw = document.getElementById('proxy-raw-request').textContent;
        const lines = raw.split('\n');
        if (lines.length > 0) {
            const parts = lines[0].split(' ');
            const method = parts[0] || 'GET';
            const path = parts[1] || '/';
            const target = document.getElementById('target-url-input').value.trim();
            const fullUrl = target + path;

            addRepeaterTab();
            document.getElementById('repeater-method').value = method;
            document.getElementById('repeater-url').value = fullUrl;
            repeaterTabs[activeRepeaterTab].method = method;
            repeaterTabs[activeRepeaterTab].url = fullUrl;
            switchTab('repeater');
            toast('Captured request sent to Repeater.', 'success');
        }
    }

    /* ============================================================
       HTTP HISTORY
       ============================================================ */

    async function refreshHistory() {
        try {
            const data = await api('GET', '/api/traffic');
            trafficLogs = Array.isArray(data) ? data : [];
            updateHistoryTable();
            updateDashboardStats();
            updateTargetSiteMap();
            setStatus(`Loaded ${trafficLogs.length} proxied traffic log(s).`);
        } catch (err) {
            toast('Failed to load traffic history: ' + err.message, 'error');
        }
    }

    function updateHistoryTable() {
        const tbody = document.getElementById('history-tbody');
        if (!tbody) return;
        const filter = (document.getElementById('history-filter')?.value || '').toLowerCase();

        const filtered = trafficLogs.filter(log => {
            if (!filter) return true;
            const searchStr = `${log.method} ${log.url || log.path} ${log.response_status || log.responseStatus}`.toLowerCase();
            return searchStr.includes(filter);
        });

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:32px;color:var(--text-tertiary)">
                ${trafficLogs.length === 0 ? 'No traffic captured yet. Route requests through port 8080.' : 'No requests match filter.'}
            </td></tr>`;
            document.getElementById('history-count').textContent = '0 items';
            return;
        }

        tbody.innerHTML = filtered.map((log, i) => {
            const method = log.method || 'GET';
            const url = log.url || log.path || '/';
            const status = log.response_status || log.responseStatus || 0;
            const bodyStr = log.response_body || log.responseBody || '';
            const bodyLen = bodyStr.length;
            const time = log.duration_ms || log.durationMs || 0;
            const ts = log.captured_at || log.capturedAt || '';
            const statusClass = status >= 200 && status < 300 ? 'badge-success' :
                               status >= 300 && status < 400 ? 'badge-info' :
                               status >= 400 && status < 500 ? 'badge-warning' :
                               status >= 500 ? 'badge-danger' : '';

            return `<tr onclick="App.selectHistoryRow(${i})" class="${selectedHistoryRow === i ? 'selected' : ''}">
                <td>${i + 1}</td>
                <td><span class="activity-method method-${method.toLowerCase()}">${escHtml(method)}</span></td>
                <td title="${escHtml(url)}"><code>${escHtml(url)}</code></td>
                <td><span class="badge ${statusClass}">${status}</span></td>
                <td>${formatBytes(bodyLen)}</td>
                <td>${time}ms</td>
                <td>${escHtml(formatTimestamp(ts))}</td>
            </tr>`;
        }).join('');

        document.getElementById('history-count').textContent = `${filtered.length} items`;
    }

    function filterHistory() {
        updateHistoryTable();
    }

    function selectHistoryRow(index) {
        selectedHistoryRow = index;
        updateHistoryTable();
        const log = trafficLogs[index];
        if (!log) return;

        const reqHeaders = log.request_headers || log.requestHeaders || {};
        const method = log.method || 'GET';
        const url = log.url || log.path || '/';
        const reqBody = log.request_body || log.requestBody || '';

        // Request Raw
        let rawReq = `${method} ${url} HTTP/1.1\n`;
        for (const [k, v] of Object.entries(reqHeaders)) {
            rawReq += `${k}: ${v}\n`;
        }
        if (reqBody) rawReq += `\n${reqBody}`;
        document.getElementById('history-request-view').textContent = rawReq;

        // Request Headers Table
        const reqHeadersTbody = document.getElementById('hist-req-headers-tbody');
        if (reqHeadersTbody) {
            reqHeadersTbody.innerHTML = Object.entries(reqHeaders).map(([k, v]) => `
                <tr><td><code>${escHtml(k)}</code></td><td><code>${escHtml(String(v))}</code></td></tr>
            `).join('');
        }

        // Request Body
        const reqBodyView = document.getElementById('hist-req-body-view');
        if (reqBodyView) reqBodyView.textContent = reqBody || '(empty body)';

        // Request Hex
        const reqHexView = document.getElementById('hist-req-hex-view');
        if (reqHexView) reqHexView.textContent = toHexDump(rawReq);

        // Response Raw & Pretty
        const respHeaders = log.response_headers || log.responseHeaders || {};
        const status = log.response_status || log.responseStatus || 0;
        const respBody = log.response_body || log.responseBody || '';

        let rawResp = `HTTP/1.1 ${status}\n`;
        for (const [k, v] of Object.entries(respHeaders)) {
            rawResp += `${k}: ${v}\n`;
        }
        rawResp += `\n${respBody}`;
        document.getElementById('history-response-view').textContent = rawResp;

        // Response Pretty
        const prettyView = document.getElementById('hist-resp-pretty-view');
        if (prettyView) {
            try {
                prettyView.textContent = JSON.stringify(JSON.parse(respBody), null, 2);
            } catch {
                prettyView.textContent = respBody;
            }
        }

        // Response Headers Table
        const respHeadersTbody = document.getElementById('hist-resp-headers-tbody');
        if (respHeadersTbody) {
            respHeadersTbody.innerHTML = Object.entries(respHeaders).map(([k, v]) => `
                <tr><td><code>${escHtml(k)}</code></td><td><code>${escHtml(String(v))}</code></td></tr>
            `).join('');
        }

        // Response Hex
        const respHexView = document.getElementById('hist-resp-hex-view');
        if (respHexView) respHexView.textContent = toHexDump(rawResp);

        // Response Render
        const renderIframe = document.getElementById('hist-render-iframe');
        if (renderIframe) {
            renderIframe.srcdoc = respBody.startsWith('<') ? respBody : `<pre style="font-family:monospace;padding:12px">${escHtml(respBody)}</pre>`;
        }
    }

    function switchHistReqPane(type) {
        const tabs = ['raw', 'headers', 'body', 'hex'];
        const container = document.getElementById('hist-req-container');
        if (!container) return;
        container.querySelectorAll('.pane-tabs .pane-tab').forEach((t, i) => {
            t.classList.toggle('active', tabs[i] === type);
        });
        container.querySelectorAll('.pane-content .pane-panel').forEach(p => {
            p.classList.toggle('active', p.id === `pane-hist-req-${type}`);
        });
    }

    function switchHistRespPane(type) {
        const tabs = ['pretty', 'raw', 'headers', 'hex', 'render'];
        const container = document.getElementById('hist-resp-container');
        if (!container) return;
        container.querySelectorAll('.pane-tabs .pane-tab').forEach((t, i) => {
            t.classList.toggle('active', tabs[i] === type);
        });
        container.querySelectorAll('.pane-content .pane-panel').forEach(p => {
            p.classList.toggle('active', p.id === `pane-hist-resp-${type}`);
        });
    }

    function sendHistoryToRepeater() {
        if (selectedHistoryRow < 0 || selectedHistoryRow >= trafficLogs.length) {
            toast('Select a request from HTTP History first.', 'warning');
            return;
        }
        const log = trafficLogs[selectedHistoryRow];
        const method = log.method || 'GET';
        const url = log.url || log.path || 'http://localhost:3000/';
        const body = log.request_body || log.requestBody || '';
        const headers = log.request_headers || log.requestHeaders || {};

        addRepeaterTab();
        document.getElementById('repeater-method').value = method;
        document.getElementById('repeater-url').value = url;
        document.getElementById('repeater-body').value = body;

        // Populate headers
        const tbody = document.getElementById('repeater-headers-tbl').querySelector('tbody');
        tbody.innerHTML = Object.entries(headers).map(([k, v]) => `
            <tr>
                <td><input type="checkbox" checked></td>
                <td><input type="text" value="${escHtml(k)}" class="kv-key"></td>
                <td><input type="text" value="${escHtml(String(v))}" class="kv-val"></td>
                <td><button class="btn-icon" onclick="this.closest('tr').remove()">×</button></td>
            </tr>
        `).join('');

        repeaterTabs[activeRepeaterTab].method = method;
        repeaterTabs[activeRepeaterTab].url = url;
        repeaterTabs[activeRepeaterTab].body = body;

        switchTab('repeater');
        toast('Request sent to Repeater.', 'success');
    }

    function sendHistoryToPolicy() {
        if (selectedHistoryRow < 0 || selectedHistoryRow >= trafficLogs.length) {
            toast('Select a request from HTTP History first.', 'warning');
            return;
        }
        const log = trafficLogs[selectedHistoryRow];
        showAddPolicyModal();
        document.getElementById('policy-name').value = `${log.method} ${log.path}`;
        document.getElementById('policy-method').value = log.method || 'GET';
        document.getElementById('policy-path').value = log.path || '/';
        document.getElementById('policy-expect').value = `{"admin": ${log.response_status || 200}, "member_a": 200, "guest": 401}`;
        if (log.request_headers) {
            document.getElementById('policy-headers').value = JSON.stringify(log.request_headers, null, 2);
        }
        if (log.request_body) {
            document.getElementById('policy-body').value = log.request_body;
        }
    }

    function copyHistoryAsCurl() {
        if (selectedHistoryRow < 0 || selectedHistoryRow >= trafficLogs.length) {
            toast('Select a request from HTTP History first.', 'warning');
            return;
        }
        const log = trafficLogs[selectedHistoryRow];
        let curl = `curl -X ${log.method} "${log.url}"`;
        const headers = log.request_headers || log.requestHeaders || {};
        for (const [k, v] of Object.entries(headers)) {
            curl += ` \\\n  -H "${k}: ${v}"`;
        }
        const body = log.request_body || log.requestBody;
        if (body) {
            curl += ` \\\n  -d '${body.replace(/'/g, "'\\''")}'`;
        }
        navigator.clipboard.writeText(curl);
        toast('cURL command copied to clipboard.', 'success');
    }

    async function clearHistory() {
        if (!confirm('Clear all HTTP traffic history?')) return;
        try {
            await api('DELETE', '/api/traffic');
            trafficLogs = [];
            selectedHistoryRow = -1;
            updateHistoryTable();
            updateDashboardStats();
            updateTargetSiteMap();
            toast('Traffic history cleared.', 'success');
        } catch (err) {
            toast('Failed to clear history: ' + err.message, 'error');
        }
    }

    /* ============================================================
       REPEATER (MULTI-TAB ENGINE)
       ============================================================ */

    function addRepeaterTab() {
        const idx = repeaterTabs.length;
        const targetUrl = document.getElementById('target-url-input')?.value || 'http://localhost:3000';
        repeaterTabs.push({
            id: idx,
            name: `Request ${idx + 1}`,
            method: 'GET',
            url: `${targetUrl}/api/users`,
            headers: [
                { name: 'Content-Type', value: 'application/json' },
                { name: 'Accept', value: 'application/json' }
            ],
            body: '',
            response: null
        });
        renderRepeaterTabs();
        switchRepeaterTab(idx);
    }

    function closeRepeaterTab(e, idx) {
        e.stopPropagation();
        if (repeaterTabs.length <= 1) {
            toast('Cannot close the only Repeater tab.', 'warning');
            return;
        }
        repeaterTabs.splice(idx, 1);
        if (activeRepeaterTab >= repeaterTabs.length) {
            activeRepeaterTab = repeaterTabs.length - 1;
        }
        renderRepeaterTabs();
        switchRepeaterTab(activeRepeaterTab);
    }

    function switchRepeaterTab(idx) {
        activeRepeaterTab = idx;
        renderRepeaterTabs();
        const tab = repeaterTabs[idx];
        if (tab) {
            document.getElementById('repeater-method').value = tab.method;
            document.getElementById('repeater-url').value = tab.url;
            document.getElementById('repeater-body').value = tab.body;
            if (tab.response) {
                displayRepeaterResponse(tab.response);
            } else {
                document.getElementById('repeater-response').textContent = 'Click "Send" to dispatch HTTP request';
                document.getElementById('repeater-raw-response').textContent = '';
                document.getElementById('repeater-response-meta').style.display = 'none';
            }
        }
    }

    function renderRepeaterTabs() {
        const bar = document.getElementById('repeater-tab-bar');
        if (!bar) return;
        bar.innerHTML = repeaterTabs.map((tab, i) => `
            <button class="repeater-tab ${i === activeRepeaterTab ? 'active' : ''}" onclick="App.switchRepeaterTab(${i})">
                ${escHtml(tab.name)}
                <span class="tab-close" onclick="App.closeRepeaterTab(event, ${i})">×</span>
            </button>
        `).join('');
    }

    function addRepeaterHeader() {
        const tbody = document.getElementById('repeater-headers-tbl').querySelector('tbody');
        const tr = document.createElement('tr');
        tr.innerHTML = `<td><input type="checkbox" checked></td>
            <td><input type="text" class="kv-key" placeholder="Header-Name"></td>
            <td><input type="text" class="kv-val" placeholder="Header Value"></td>
            <td><button class="btn-icon" onclick="this.closest('tr').remove()">×</button></td>`;
        tbody.appendChild(tr);
    }

    function switchRepeaterReqPane(pane) {
        document.querySelectorAll('#panel-repeater .split-left .pane-tabs .pane-tab').forEach((t, i) => {
            const tabs = ['headers', 'body', 'raw'];
            t.classList.toggle('active', tabs[i] === pane);
        });

        const headersSec = document.getElementById('rep-req-headers-section');
        const rawSec = document.getElementById('rep-req-raw-section');
        if (pane === 'raw') {
            headersSec.style.display = 'none';
            rawSec.style.display = 'flex';
            // Build raw
            const method = document.getElementById('repeater-method').value;
            const url = document.getElementById('repeater-url').value.trim();
            const body = document.getElementById('repeater-body').value;
            let raw = `${method} ${url} HTTP/1.1\n`;
            document.querySelectorAll('#repeater-headers-tbl tbody tr').forEach(r => {
                const k = r.querySelector('.kv-key').value.trim();
                const v = r.querySelector('.kv-val').value;
                if (k) raw += `${k}: ${v}\n`;
            });
            if (body) raw += `\n${body}`;
            document.getElementById('repeater-raw-editor').value = raw;
        } else {
            headersSec.style.display = 'block';
            rawSec.style.display = 'none';
        }
    }

    function switchRepRespPane(type) {
        const tabs = ['pretty', 'raw', 'headers', 'hex', 'render'];
        document.querySelectorAll('#rep-resp-tabs .pane-tab').forEach((t, i) => {
            t.classList.toggle('active', tabs[i] === type);
        });
        document.querySelectorAll('#repeater-response-pane .pane-content .pane-panel').forEach(p => {
            p.classList.toggle('active', p.id === `pane-rep-${type}`);
        });
    }

    async function sendRepeater() {
        const method = document.getElementById('repeater-method').value;
        const url = document.getElementById('repeater-url').value.trim();
        const body = document.getElementById('repeater-body').value.trim();

        if (!url) { toast('Please specify a destination URL.', 'warning'); return; }

        const headers = {};
        document.querySelectorAll('#repeater-headers-tbl tbody tr').forEach(row => {
            const enabled = row.querySelector('input[type="checkbox"]').checked;
            if (!enabled) return;
            const key = row.querySelector('.kv-key').value.trim();
            const val = row.querySelector('.kv-val').value;
            if (key) headers[key] = val;
        });

        repeaterTabs[activeRepeaterTab].method = method;
        repeaterTabs[activeRepeaterTab].url = url;
        repeaterTabs[activeRepeaterTab].body = body;

        setStatus(`Sending ${method} ${url}…`);
        document.getElementById('repeater-response').textContent = 'Connecting to target server…';

        try {
            const startTs = Date.now();
            const data = await api('POST', '/api/repeater/send', { method, url, headers, body: body || null });
            const elapsed = Date.now() - startTs;

            const result = { ...data, clientTime: elapsed };
            repeaterTabs[activeRepeaterTab].response = result;
            displayRepeaterResponse(result);
            setStatus(`Response received: ${data.status || '?'} in ${elapsed}ms`);
        } catch (err) {
            document.getElementById('repeater-response').textContent = `Request Error: ${err.message}`;
            document.getElementById('repeater-response-meta').style.display = 'none';
            toast('Repeater request failed: ' + err.message, 'error');
        }
    }

    function displayRepeaterResponse(result) {
        const metaEl = document.getElementById('repeater-response-meta');
        metaEl.style.display = 'flex';

        const status = result.status || result.response_status || 0;
        const statusEl = document.getElementById('repeater-resp-status');
        statusEl.textContent = `${status} ${result.statusText ? result.statusText.replace(/^\d+\s*/, '') : ''}`;
        statusEl.className = 'badge badge-status ' + (status >= 200 && status < 300 ? 'badge-success' :
                             status >= 400 ? 'badge-danger' : 'badge-warning');

        document.getElementById('repeater-resp-time').textContent = `${result.duration_ms || result.clientTime || 0}ms`;
        const bodyStr = result.body || result.response_body || '';
        document.getElementById('repeater-resp-size').textContent = formatBytes(bodyStr.length);

        // Pretty
        let formatted;
        try { formatted = JSON.stringify(JSON.parse(bodyStr), null, 2); } catch { formatted = bodyStr; }
        document.getElementById('repeater-response').textContent = formatted;

        // Raw
        let raw = `HTTP/1.1 ${status}\n`;
        const headers = result.headers || result.response_headers || {};
        for (const [k, v] of Object.entries(headers)) {
            raw += `${k}: ${v}\n`;
        }
        raw += `\n${bodyStr}`;
        document.getElementById('repeater-raw-response').textContent = raw;

        // Headers Table
        const headersTbody = document.getElementById('repeater-headers-tbody');
        if (headersTbody) {
            headersTbody.innerHTML = Object.entries(headers).map(([k, v]) => `
                <tr><td><code>${escHtml(k)}</code></td><td><code>${escHtml(String(v))}</code></td></tr>
            `).join('');
        }

        // Hex
        const hexEl = document.getElementById('repeater-hex-response');
        if (hexEl) hexEl.textContent = toHexDump(raw);

        // Render HTML
        const renderIframe = document.getElementById('repeater-render-iframe');
        if (renderIframe) {
            renderIframe.srcdoc = bodyStr.startsWith('<') ? bodyStr : `<pre style="font-family:monospace;padding:12px">${escHtml(bodyStr)}</pre>`;
        }
    }

    function sendRepeaterToPolicy() {
        const tab = repeaterTabs[activeRepeaterTab];
        if (!tab) return;
        showAddPolicyModal();
        let path = tab.url;
        try {
            const u = new URL(tab.url);
            path = u.pathname + u.search;
        } catch {}

        document.getElementById('policy-name').value = `${tab.method} ${path}`;
        document.getElementById('policy-method').value = tab.method;
        document.getElementById('policy-path').value = path;
        document.getElementById('policy-expect').value = '{"admin": 200, "member_a": 200, "guest": 401}';
        if (tab.body) document.getElementById('policy-body').value = tab.body;
    }

    /* ============================================================
       AUTH MATRIX (RBAC CONTRACT VERIFICATION)
       ============================================================ */

    async function runMatrix() {
        const targetUrl = document.getElementById('target-url-input').value.trim() || 'http://localhost:3000';
        setStatus('Running automated RBAC matrix verification…');
        const summaryEl = document.getElementById('matrix-summary');
        summaryEl.innerHTML = '<span style="color:var(--warning)">⏳ Executing contract matrix against ' + escHtml(targetUrl) + '…</span>';

        try {
            const data = await api('POST', '/api/matrix/run', { target_base_url: targetUrl });
            matrixResults = data;
            renderMatrixGrid(data);
            toast('AuthMatrix verification complete.', 'success');
            setStatus('AuthMatrix verification completed successfully.');
        } catch (err) {
            toast('Matrix verification failed: ' + err.message, 'error');
            summaryEl.innerHTML = `<span style="color:var(--danger)">❌ Error: ${escHtml(err.message)}</span>`;
            setStatus('Matrix verification encountered an error.');
        }
    }

    function renderMatrixGrid(data) {
        const container = document.getElementById('matrix-grid-container');
        const results = data.results || data;
        const summaryEl = document.getElementById('matrix-summary');

        if (!Array.isArray(results) || results.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No results. Ensure security roles and endpoint policies are defined.</p></div>';
            summaryEl.innerHTML = '';
            return;
        }

        // Resiliently resolve properties
        const roleNames = [...new Set(results.map(r => r.role || r.role_name || r.roleName))];
        const endpoints = [];
        const epMap = {};

        results.forEach((r, idx) => {
            const role = r.role || r.role_name || r.roleName || 'default';
            const method = r.method || r.endpoint_method || r.endpointMethod || 'GET';
            const path = r.path || r.endpoint_path || r.endpointPath || '/';
            const key = `${method} ${path}`;

            if (!epMap[key]) {
                epMap[key] = {};
                endpoints.push({ method, path, key, name: r.name || r.endpoint_name || r.endpointName || key });
            }
            epMap[key][role] = { ...r, resultIndex: idx };
        });

        let passCount = 0, failCount = 0, mismatchCount = 0, errorCount = 0;
        results.forEach(r => {
            const v = (r.verdict || '').toUpperCase();
            if (v === 'PASS') passCount++;
            else if (v === 'REGRESSION_UNAUTHORIZED_ACCESS') failCount++;
            else if (v === 'STATUS_MISMATCH') mismatchCount++;
            else errorCount++;
        });

        summaryEl.innerHTML = `
            <span class="badge badge-success">✓ ${passCount} Passed</span>
            <span class="badge badge-danger">✗ ${failCount} Critical Regressions</span>
            <span class="badge badge-warning">⚠ ${mismatchCount} Mismatches</span>
            <span class="badge">${errorCount} Errors</span>
            <span class="badge">Total Tests: ${results.length}</span>
        `;

        document.getElementById('stat-pass-count').textContent = passCount;
        document.getElementById('stat-fail-count').textContent = failCount;

        let html = `<table class="matrix-table">
            <thead><tr>
                <th>Method</th>
                <th>Endpoint Contract</th>
                ${roleNames.map(r => `<th>${escHtml(r)}</th>`).join('')}
            </tr></thead><tbody>`;

        endpoints.forEach(ep => {
            html += `<tr>
                <td><span class="activity-method method-${ep.method.toLowerCase()}">${escHtml(ep.method)}</span></td>
                <td><strong>${escHtml(ep.name)}</strong><br><code style="font-size:11px">${escHtml(ep.path)}</code></td>`;
            roleNames.forEach(role => {
                const r = epMap[ep.key][role];
                if (!r) {
                    html += '<td>—</td>';
                    return;
                }
                const v = (r.verdict || '').toUpperCase();
                const actual = r.actual_status || r.actualStatus || 0;
                const expected = r.expected_status || r.expectedStatus || 200;
                let cellClass, icon, label;

                if (v === 'PASS') {
                    cellClass = 'cell-pass'; icon = '✓'; label = `${actual} OK`;
                } else if (v === 'REGRESSION_UNAUTHORIZED_ACCESS') {
                    cellClass = 'cell-fail'; icon = '🚨'; label = `${actual} (Exp ${expected}) BOLA`;
                } else if (v === 'STATUS_MISMATCH') {
                    cellClass = 'cell-mismatch'; icon = '⚠'; label = `${actual} (Exp ${expected})`;
                } else {
                    cellClass = 'cell-error'; icon = '⊘'; label = r.error_message || r.errorMessage || 'Error';
                }

                html += `<td>
                    <span class="matrix-cell ${cellClass}" title="Click to inspect security finding" onclick="App.inspectMatrixCell(${r.resultIndex})">
                        ${icon} ${escHtml(label)}
                    </span>
                </td>`;
            });
            html += '</tr>';
        });

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    function refreshMatrix() {
        if (matrixResults) renderMatrixGrid(matrixResults);
    }

    function inspectMatrixCell(index) {
        if (!matrixResults) return;
        const results = matrixResults.results || matrixResults;
        const finding = results[index];
        if (!finding) return;

        activeFinding = finding;
        const drawer = document.getElementById('matrix-drawer');
        const verdict = (finding.verdict || '').toUpperCase();
        const role = finding.role || finding.role_name || finding.roleName;
        const method = finding.method || finding.endpoint_method || finding.endpointMethod;
        const path = finding.path || finding.endpoint_path || finding.endpointPath;
        const actual = finding.actual_status || finding.actualStatus;
        const expected = finding.expected_status || finding.expectedStatus;

        document.getElementById('drawer-endpoint').textContent = `${method} ${path}`;
        document.getElementById('drawer-role').textContent = role;
        document.getElementById('drawer-expected').textContent = expected;
        document.getElementById('drawer-actual').textContent = `${actual}`;
        document.getElementById('drawer-duration').textContent = `${finding.duration_ms || finding.durationMs || 0} ms`;

        // Match role header
        const matchedRole = roles.find(r => r.name === role);
        const headerInfo = matchedRole
            ? `${matchedRole.headerName || matchedRole.header_name || 'Authorization'}: ${matchedRole.headerValue || matchedRole.header_value || '(none)'}`
            : '(No custom credentials configured)';
        document.getElementById('drawer-auth-header').textContent = headerInfo;

        const banner = document.getElementById('drawer-alert-banner');
        const heading = document.getElementById('drawer-alert-heading');
        const desc = document.getElementById('drawer-alert-desc');
        const icon = document.getElementById('drawer-verdict-icon');

        if (verdict === 'REGRESSION_UNAUTHORIZED_ACCESS') {
            banner.className = 'finding-alert finding-alert-critical';
            heading.textContent = '🚨 CRITICAL VULNERABILITY: Broken Object Level Authorization (BOLA)';
            desc.textContent = `Endpoint returned HTTP ${actual} for identity '${role}', but security policy strictly requires HTTP ${expected}. Unauthorized users have access to restricted resources!`;
            icon.textContent = '🚨';
        } else if (verdict === 'PASS') {
            banner.className = 'finding-alert finding-alert-pass';
            heading.textContent = '✓ Contract Satisfied';
            desc.textContent = `Actual response HTTP ${actual} matches expected contract status ${expected} for role '${role}'.`;
            icon.textContent = '✓';
        } else {
            banner.className = 'finding-alert finding-alert-warning';
            heading.textContent = '⚠ Status Code Mismatch';
            desc.textContent = `Expected HTTP ${expected}, but upstream responded with HTTP ${actual}. Check upstream API route implementation.`;
            icon.textContent = '⚠';
        }

        drawer.classList.add('open');
    }

    function closeMatrixDrawer() {
        const drawer = document.getElementById('matrix-drawer');
        if (drawer) drawer.classList.remove('open');
    }

    function sendFindingToRepeater() {
        if (!activeFinding) return;
        const targetUrl = document.getElementById('target-url-input').value.trim();
        const method = activeFinding.method || activeFinding.endpoint_method || activeFinding.endpointMethod || 'GET';
        const path = activeFinding.path || activeFinding.endpoint_path || activeFinding.endpointPath || '/';
        const fullUrl = targetUrl + (path.startsWith('/') ? path : '/' + path);

        addRepeaterTab();
        document.getElementById('repeater-method').value = method;
        document.getElementById('repeater-url').value = fullUrl;

        // Injected role credentials
        const role = activeFinding.role || activeFinding.role_name || activeFinding.roleName;
        const matchedRole = roles.find(r => r.name === role);
        if (matchedRole) {
            const hName = matchedRole.headerName || matchedRole.header_name || 'Authorization';
            const hVal = matchedRole.headerValue || matchedRole.header_value || '';
            const tbody = document.getElementById('repeater-headers-tbl').querySelector('tbody');
            tbody.innerHTML += `
                <tr>
                    <td><input type="checkbox" checked></td>
                    <td><input type="text" value="${escHtml(hName)}" class="kv-key"></td>
                    <td><input type="text" value="${escHtml(hVal)}" class="kv-val"></td>
                    <td><button class="btn-icon" onclick="this.closest('tr').remove()">×</button></td>
                </tr>
            `;
        }

        closeMatrixDrawer();
        switchTab('repeater');
        toast(`Finding sent to Repeater for role '${role}'.`, 'success');
    }

    /* ============================================================
       DECODER TOOL (TRANSFORMATION SERVICE)
       ============================================================ */

    function initDecoderListeners() {
        const inp = document.getElementById('decoder-input');
        if (inp) {
            inp.addEventListener('input', () => {
                document.getElementById('decoder-input-len').textContent = `${inp.value.length} chars`;
            });
        }
    }

    async function runDecoder(action) {
        const input = document.getElementById('decoder-input').value;
        if (!input) { toast('Enter input text to decode/encode.', 'warning'); return; }

        try {
            // First attempt backend service
            const data = await api('POST', '/api/decoder', { input, action });
            if (data && data.result !== undefined) {
                document.getElementById('decoder-output').value = data.result;
                toast(`Applied ${action}.`, 'success');
                return;
            }
        } catch {
            // Client-side fallback
            try {
                let res = '';
                if (action === 'url_encode') res = encodeURIComponent(input);
                else if (action === 'url_decode') res = decodeURIComponent(input);
                else if (action === 'base64_encode') res = btoa(unescape(encodeURIComponent(input)));
                else if (action === 'base64_decode') res = decodeURIComponent(escape(atob(input.trim())));
                else if (action === 'hex_encode') res = Array.from(new TextEncoder().encode(input)).map(b => b.toString(16).padStart(2, '0')).join('');
                else if (action === 'hex_decode') {
                    const clean = input.replace(/\s+/g, '');
                    const bytes = new Uint8Array(clean.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                    res = new TextDecoder().decode(bytes);
                } else if (action === 'jwt_decode') {
                    const parts = input.trim().split('.');
                    if (parts.length >= 2) {
                        const h = decodeURIComponent(escape(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/'))));
                        const p = decodeURIComponent(escape(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'))));
                        res = `HEADER:\n${JSON.stringify(JSON.parse(h), null, 2)}\n\nPAYLOAD:\n${JSON.stringify(JSON.parse(p), null, 2)}\n\nSIGNATURE:\n${parts[2] || ''}`;
                    } else {
                        res = 'Invalid JWT token format';
                    }
                } else {
                    res = 'Action requires backend: ' + action;
                }
                document.getElementById('decoder-output').value = res;
                toast(`Applied ${action} (client-side).`, 'success');
            } catch (e) {
                toast('Decoding error: ' + e.message, 'error');
            }
        }
    }

    function applyDecoderToInput() {
        const out = document.getElementById('decoder-output').value;
        if (!out) return;
        document.getElementById('decoder-input').value = out;
        document.getElementById('decoder-input-len').textContent = `${out.length} chars`;
        toast('Output copied to input for multi-stage transform.', 'info');
    }

    function copyDecoderOutput() {
        const out = document.getElementById('decoder-output').value;
        if (!out) return;
        navigator.clipboard.writeText(out);
        toast('Result copied to clipboard.', 'success');
    }

    /* ============================================================
       COMPARER TOOL (VISUAL DIFF SERVICE)
       ============================================================ */

    function runComparer(mode) {
        const t1 = document.getElementById('comparer-input-1').value;
        const t2 = document.getElementById('comparer-input-2').value;
        const out = document.getElementById('comparer-diff-output');

        if (!t1 && !t2) {
            toast('Paste content into Item 1 and Item 2 to compare.', 'warning');
            return;
        }

        if (mode === 'lines') {
            const lines1 = t1.split('\n');
            const lines2 = t2.split('\n');
            let diffHtml = '';
            let changes = 0;
            const max = Math.max(lines1.length, lines2.length);

            for (let i = 0; i < max; i++) {
                const l1 = lines1[i];
                const l2 = lines2[i];

                if (l1 === undefined) {
                    diffHtml += `<div class="diff-added">+ Line ${i + 1}: ${escHtml(l2)}</div>`;
                    changes++;
                } else if (l2 === undefined) {
                    diffHtml += `<div class="diff-removed">- Line ${i + 1}: ${escHtml(l1)}</div>`;
                    changes++;
                } else if (l1 !== l2) {
                    diffHtml += `<div class="diff-modified">~ Line ${i + 1} (Item 1): ${escHtml(l1)}</div>`;
                    diffHtml += `<div class="diff-modified">~ Line ${i + 1} (Item 2): ${escHtml(l2)}</div>`;
                    changes++;
                } else {
                    diffHtml += `<div>  Line ${i + 1}: ${escHtml(l1)}</div>`;
                }
            }
            out.innerHTML = diffHtml || 'Items are identical.';
            document.getElementById('comparer-stats').textContent = `${changes} line differences found`;
        } else {
            // Words mode
            const w1 = t1.split(/\s+/);
            const w2 = t2.split(/\s+/);
            let diffHtml = '';
            let changes = 0;
            const max = Math.max(w1.length, w2.length);

            for (let i = 0; i < max; i++) {
                const word1 = w1[i];
                const word2 = w2[i];
                if (word1 !== word2) {
                    diffHtml += `<span class="diff-removed">${escHtml(word1 || '')}</span> <span class="diff-added">${escHtml(word2 || '')}</span> `;
                    changes++;
                } else {
                    diffHtml += `${escHtml(word1)} `;
                }
            }
            out.innerHTML = diffHtml || 'Items are identical.';
            document.getElementById('comparer-stats').textContent = `${changes} word differences found`;
        }
        toast(`Comparison complete (${mode}).`, 'info');
    }

    function clearComparer() {
        document.getElementById('comparer-input-1').value = '';
        document.getElementById('comparer-input-2').value = '';
        document.getElementById('comparer-diff-output').textContent = 'Paste content and click Compare to inspect visual diff.';
        document.getElementById('comparer-stats').textContent = 'Ready';
    }

    /* ============================================================
       ROLES
       ============================================================ */

    async function refreshRoles() {
        try {
            const data = await api('GET', '/api/roles');
            roles = Array.isArray(data) ? data : [];
            renderRolesGrid();
            const badge = document.getElementById('role-count-badge');
            if (badge) badge.textContent = `${roles.length} roles`;
            document.getElementById('stat-role-count').textContent = roles.length;
        } catch (err) {
            toast('Failed to load roles: ' + err.message, 'error');
        }
    }

    function renderRolesGrid() {
        const grid = document.getElementById('roles-grid');
        if (!grid) return;
        if (roles.length === 0) {
            grid.innerHTML = `<div class="empty-state">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>
                <p>No roles defined. Click "Add Role" to configure access identities.</p>
            </div>`;
            return;
        }

        grid.innerHTML = roles.map(role => {
            const name = role.name || 'Unnamed';
            const headerName = role.header_name || role.headerName || 'Authorization';
            const headerValue = role.header_value || role.headerValue || '';
            const maskedValue = headerValue.length > 25 ? headerValue.substring(0, 25) + '…' : (headerValue || '(none)');
            const id = role.id || '';
            const roleColor = stringToColor(name);

            return `<div class="role-card" style="border-left: 3px solid ${roleColor}">
                <div class="role-card-header">
                    <span class="role-card-name" style="color: ${roleColor}">${escHtml(name)}</span>
                    <button class="btn btn-xs btn-danger" onclick="App.deleteRole('${escHtml(id)}')">Delete</button>
                </div>
                <div class="role-card-detail">
                    <span class="role-card-label">Auth Header</span>
                    <span class="role-card-value"><code>${escHtml(headerName)}: ${escHtml(maskedValue)}</code></span>
                </div>
                <div class="role-card-detail">
                    <span class="role-card-label">Created</span>
                    <span class="role-card-value">${escHtml(formatTimestamp(role.created_at || role.createdAt || ''))}</span>
                </div>
            </div>`;
        }).join('');
    }

    function showAddRoleModal() {
        document.getElementById('role-name').value = '';
        document.getElementById('role-header-name').value = 'Authorization';
        document.getElementById('role-header-value').value = '';
        openModal('modal-add-role');
    }

    async function addRole() {
        const name = document.getElementById('role-name').value.trim();
        const headerName = document.getElementById('role-header-name').value.trim();
        const headerValue = document.getElementById('role-header-value').value.trim();

        if (!name) { toast('Role identifier is required.', 'warning'); return; }

        try {
            await api('POST', '/api/roles', {
                name,
                header_name: headerName || 'Authorization',
                header_value: headerValue
            });
            closeModal();
            refreshRoles();
            toast(`Role "${name}" saved successfully.`, 'success');
        } catch (err) {
            toast('Failed to save role: ' + err.message, 'error');
        }
    }

    async function deleteRole(id) {
        if (!confirm('Delete this security role?')) return;
        try {
            await api('DELETE', `/api/roles/${id}`);
            refreshRoles();
            toast('Role deleted.', 'success');
        } catch (err) {
            toast('Failed to delete role: ' + err.message, 'error');
        }
    }

    /* ============================================================
       POLICIES & ENDPOINTS
       ============================================================ */

    async function refreshPolicies() {
        try {
            const data = await api('GET', '/api/policies');
            policies = Array.isArray(data) ? data : [];
            renderPoliciesTable();
            const badge = document.getElementById('policy-count-badge');
            if (badge) badge.textContent = `${policies.length} policies`;
        } catch (err) {
            toast('Failed to load policies: ' + err.message, 'error');
        }
    }

    function renderPoliciesTable() {
        const tbody = document.getElementById('policies-tbody');
        if (!tbody) return;
        if (policies.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--text-tertiary)">
                No endpoint policies defined. Click "Add Policy" to declare RBAC rules.
            </td></tr>`;
            return;
        }

        tbody.innerHTML = policies.map(p => {
            const expect = p.expect || {};
            const expectBadges = Object.entries(expect).map(([role, status]) => {
                const cls = status >= 200 && status < 300 ? 'badge-success' :
                           status >= 400 ? 'badge-danger' : 'badge-warning';
                return `<span class="badge ${cls}" style="margin:2px">${escHtml(role)}: ${status}</span>`;
            }).join(' ');

            return `<tr>
                <td><strong>${escHtml(p.name || '')}</strong></td>
                <td><span class="activity-method method-${(p.method || '').toLowerCase()}">${escHtml(p.method || '')}</span></td>
                <td><code>${escHtml(p.path || '')}</code></td>
                <td>${expectBadges || '<span style="color:var(--text-tertiary)">(none)</span>'}</td>
                <td>
                    <button class="btn btn-xs btn-danger" onclick="App.deletePolicy('${escHtml(p.id || '')}')">Delete</button>
                </td>
            </tr>`;
        }).join('');
    }

    function showAddPolicyModal() {
        document.getElementById('policy-name').value = '';
        document.getElementById('policy-method').value = 'GET';
        document.getElementById('policy-path').value = '';
        document.getElementById('policy-expect').value = '{"admin": 200, "member_a": 200, "guest": 401}';
        document.getElementById('policy-headers').value = '';
        document.getElementById('policy-body').value = '';
        openModal('modal-add-policy');
    }

    async function addPolicy() {
        const name = document.getElementById('policy-name').value.trim();
        const method = document.getElementById('policy-method').value;
        const path = document.getElementById('policy-path').value.trim();
        const expectStr = document.getElementById('policy-expect').value.trim();
        const headersStr = document.getElementById('policy-headers').value.trim();
        const body = document.getElementById('policy-body').value.trim();

        if (!name || !path) { toast('Policy name and path pattern are required.', 'warning'); return; }

        let expect = {};
        if (expectStr) {
            try { expect = JSON.parse(expectStr); } catch { toast('Invalid JSON in Expected Status.', 'error'); return; }
        }

        let headers = {};
        if (headersStr) {
            try { headers = JSON.parse(headersStr); } catch { toast('Invalid JSON in Custom Headers.', 'error'); return; }
        }

        try {
            await api('POST', '/api/policies', { name, method, path, expect, headers, body: body || null });
            closeModal();
            refreshPolicies();
            toast(`Policy "${name}" created successfully.`, 'success');
        } catch (err) {
            toast('Failed to create policy: ' + err.message, 'error');
        }
    }

    async function deletePolicy(id) {
        if (!confirm('Delete this policy contract?')) return;
        try {
            await api('DELETE', `/api/policies/${id}`);
            refreshPolicies();
            toast('Policy deleted.', 'success');
        } catch (err) {
            toast('Failed to delete policy: ' + err.message, 'error');
        }
    }

    /* ============================================================
       CONFIG IMPORT & EXPORT
       ============================================================ */

    async function importConfig() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.yaml,.yml,.json';
        input.onchange = async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            const text = await file.text();
            try {
                const res = await api('POST', '/api/config/import', { content: text, filename: file.name });
                toast(`Config imported: ${res.importedRoles || 0} roles, ${res.importedEndpoints || 0} policies.`, 'success');
                refreshRoles();
                refreshPolicies();
                loadConfig();
            } catch (err) {
                toast('Import failed: ' + err.message, 'error');
            }
        };
        input.click();
    }

    async function exportConfig() {
        try {
            const data = await api('GET', '/api/config/export');
            const yamlStr = typeof data === 'object' && data.yaml ? data.yaml : (typeof data === 'string' ? data : JSON.stringify(data, null, 2));
            const blob = new Blob([yamlStr], { type: 'text/yaml' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = '.authmatrix.yaml';
            a.click();
            URL.revokeObjectURL(url);
            toast('Configuration exported as .authmatrix.yaml', 'success');
        } catch (err) {
            toast('Export failed: ' + err.message, 'error');
        }
    }

    /* ============================================================
       DASHBOARD & STATUS
       ============================================================ */

    function updateDashboardStats() {
        document.getElementById('stat-total-requests').textContent = trafficLogs.length;
    }

    function addActivityItem(log) {
        const feed = document.getElementById('recent-activity');
        if (!feed) return;
        if (feed.querySelector('.empty-state')) {
            feed.innerHTML = '';
        }
        const method = log.method || 'GET';
        const url = log.url || log.path || '/';
        const status = log.response_status || log.responseStatus || 0;
        const time = log.duration_ms || log.durationMs || 0;

        const item = document.createElement('div');
        item.className = 'activity-item';
        item.innerHTML = `
            <span class="activity-method method-${method.toLowerCase()}">${escHtml(method)}</span>
            <span style="flex:1;overflow:hidden;text-overflow:ellipsis"><code>${escHtml(url)}</code></span>
            <span class="badge ${status >= 200 && status < 300 ? 'badge-success' : status >= 400 ? 'badge-danger' : 'badge-warning'}">${status}</span>
            <span style="color:var(--text-tertiary);font-size:11px">${time}ms</span>
        `;
        feed.insertBefore(item, feed.firstChild);

        while (feed.children.length > 25) {
            feed.removeChild(feed.lastChild);
        }
    }

    /* ============================================================
       SETTINGS & CONTROLS
       ============================================================ */

    async function setTarget() {
        const val = document.getElementById('target-url-input').value.trim();
        if (!val) return;
        try {
            await api('PUT', '/api/config', { targetHost: val });
            document.getElementById('setting-target-url').value = val;
            const sitemapHost = document.getElementById('sitemap-host-label');
            if (sitemapHost) sitemapHost.textContent = val;
            toast(`Proxy target host set to ${val}`, 'success');
        } catch (e) {
            toast('Failed to set target: ' + e.message, 'error');
        }
    }

    async function saveTargetSetting() {
        const val = document.getElementById('setting-target-url').value.trim();
        if (!val) return;
        document.getElementById('target-url-input').value = val;
        await setTarget();
    }

    function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        toast(`Theme switched to ${theme}`, 'info');
    }

    function setFontSize(size) {
        document.documentElement.style.setProperty('--font-size', size + 'px');
    }

    function showProxySettings() {
        switchTab('settings');
    }

    function showAbout() {
        openModal('modal-about');
    }

    function showShortcuts() {
        toast('Shortcuts: Ctrl+Shift+ [D:Dash, T:Target, P:Proxy, H:History, R:Repeater, M:Matrix, C:Decoder, X:Comparer]', 'info');
    }

    async function clearAllData() {
        if (!confirm('This will purge ALL captured traffic, roles, and policies. Continue?')) return;
        try {
            await api('DELETE', '/api/traffic');
            await api('DELETE', '/api/roles');
            await api('DELETE', '/api/policies');
            trafficLogs = [];
            roles = [];
            policies = [];
            matrixResults = null;
            selectedHistoryRow = -1;
            updateHistoryTable();
            renderRolesGrid();
            renderPoliciesTable();
            updateTargetSiteMap();
            updateDashboardStats();
            document.getElementById('matrix-grid-container').innerHTML = `
                <div class="empty-state">
                    <h3>Declarative RBAC Verification Engine</h3>
                    <p>All data has been cleared.</p>
                </div>
            `;
            document.getElementById('matrix-summary').innerHTML = '';
            document.getElementById('stat-role-count').textContent = '0';
            document.getElementById('stat-pass-count').textContent = '0';
            document.getElementById('stat-fail-count').textContent = '0';
            toast('All database records cleared.', 'success');
        } catch (err) {
            toast('Failed to clear data: ' + err.message, 'error');
        }
    }

    /* ============================================================
       MODALS & NOTIFICATIONS
       ============================================================ */

    function openModal(id) {
        document.getElementById('modal-overlay').classList.add('show');
        document.getElementById(id).classList.add('show');
    }

    function closeModal() {
        document.getElementById('modal-overlay').classList.remove('show');
        document.querySelectorAll('.modal').forEach(m => m.classList.remove('show'));
    }

    function toast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        if (!container) return;
        const el = document.createElement('div');
        el.className = `toast toast-${type}`;
        const icons = { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' };
        el.innerHTML = `<strong>${icons[type] || 'ℹ'}</strong> <span>${escHtml(message)}</span>`;
        container.appendChild(el);
        setTimeout(() => {
            el.classList.add('toast-dismiss');
            setTimeout(() => el.remove(), 300);
        }, 4000);
    }

    function setStatus(msg) {
        const el = document.getElementById('status-message');
        if (el) el.textContent = msg;
    }

    function startStatusUpdater() {
        setInterval(() => {
            const elapsed = Math.floor((Date.now() - startTime) / 1000);
            const mins = Math.floor(elapsed / 60);
            const secs = elapsed % 60;
            const uptimeEl = document.getElementById('status-uptime');
            if (uptimeEl) uptimeEl.textContent = `Uptime: ${mins}m ${secs}s`;

            if (performance && performance.memory) {
                const mb = Math.round(performance.memory.usedJSHeapSize / 1048576);
                const memEl = document.getElementById('status-memory');
                if (memEl) memEl.textContent = `Memory: ${mb} MB`;
            }
        }, 1000);
    }

    function setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.shiftKey) {
                switch (e.key.toUpperCase()) {
                    case 'D': e.preventDefault(); switchTab('dashboard'); break;
                    case 'T': e.preventDefault(); switchTab('target'); break;
                    case 'P': e.preventDefault(); switchTab('proxy'); break;
                    case 'H': e.preventDefault(); switchTab('history'); break;
                    case 'R': e.preventDefault(); switchTab('repeater'); break;
                    case 'M': e.preventDefault(); switchTab('matrix'); break;
                    case 'O': e.preventDefault(); switchTab('roles'); break;
                    case 'L': e.preventDefault(); switchTab('policies'); break;
                    case 'C': e.preventDefault(); switchTab('decoder'); break;
                    case 'X': e.preventDefault(); switchTab('comparer'); break;
                }
            }
            if (e.key === 'Escape') {
                closeModal();
                closeMatrixDrawer();
            }
        });
    }

    /* ============================================================
       HEX DUMP & FORMATTING UTILITIES
       ============================================================ */

    function toHexDump(str) {
        if (!str) return '';
        const bytes = new TextEncoder().encode(str);
        let out = '';
        for (let i = 0; i < bytes.length; i += 16) {
            const offset = i.toString(16).padStart(8, '0');
            let hex = '';
            let ascii = '';
            for (let j = 0; j < 16; j++) {
                if (i + j < bytes.length) {
                    const b = bytes[i + j];
                    hex += b.toString(16).padStart(2, '0') + ' ';
                    ascii += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
                } else {
                    hex += '   ';
                }
                if (j === 7) hex += ' ';
            }
            out += `${offset}  ${hex} |${ascii}|\n`;
            if (i >= 4096) {
                out += `... (truncated at 4 KB)\n`;
                break;
            }
        }
        return out;
    }

    function escHtml(str) {
        if (typeof str !== 'string') return String(str || '');
        return str.replace(/&/g, '&amp;')
                  .replace(/</g, '&lt;')
                  .replace(/>/g, '&gt;')
                  .replace(/"/g, '&quot;')
                  .replace(/'/g, '&#39;');
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / 1048576).toFixed(1) + ' MB';
    }

    function formatTimestamp(ts) {
        if (!ts) return '—';
        try {
            const d = new Date(ts);
            if (isNaN(d.getTime())) return ts;
            return d.toLocaleTimeString() + ' ' + d.toLocaleDateString();
        } catch { return ts; }
    }

    function stringToColor(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = str.charCodeAt(i) + ((hash << 5) - hash);
        }
        const h = Math.abs(hash % 360);
        return `hsl(${h}, 70%, 60%)`;
    }

    document.addEventListener('DOMContentLoaded', init);

    /* ============================================================
       PUBLIC API EXPORTS
       ============================================================ */

    return {
        switchTab,
        switchProxyPane,
        switchProxyRespPane,
        switchHistReqPane,
        switchHistRespPane,
        switchRepeaterReqPane,
        switchRepRespPane,
        toggleIntercept,
        forwardRequest,
        dropRequest,
        sendToRepeater,
        selectHistoryRow,
        filterHistory,
        refreshHistory,
        clearHistory,
        sendHistoryToRepeater,
        sendHistoryToPolicy,
        copyHistoryAsCurl,
        filterHistoryByPath,
        refreshTargetSiteMap,
        exportTargetSiteMap,
        sendTargetToRepeater,
        createPolicyFromTarget,
        showAddRoleModal,
        addRole,
        deleteRole,
        refreshRoles,
        showAddPolicyModal,
        addPolicy,
        deletePolicy,
        refreshPolicies,
        runMatrix,
        refreshMatrix,
        inspectMatrixCell,
        closeMatrixDrawer,
        sendFindingToRepeater,
        addRepeaterTab,
        closeRepeaterTab,
        switchRepeaterTab,
        addRepeaterHeader,
        sendRepeater,
        sendRepeaterToPolicy,
        runDecoder,
        applyDecoderToInput,
        copyDecoderOutput,
        runComparer,
        clearComparer,
        importConfig,
        exportConfig,
        setTarget,
        saveTargetSetting,
        setTheme,
        setFontSize,
        showProxySettings,
        showAbout,
        showShortcuts,
        clearAllData,
        closeModal
    };
})();
