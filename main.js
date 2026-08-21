// ==========================================
// SAFE API WRAPPER
// Handles errors & secure cookies natively
// ==========================================
async function safeFetch(url, options = {}) {
    options.credentials = "include";
    try {
        const response = await fetch(url, options);
        
        // Handle graceful rate limiting
        if (response.status === 429) {
            throw new Error("Rate limit exceeded. Please wait a moment.");
        }
        
        let data = null;
        const contentType = response.headers.get("content-type");
        
        if (contentType && contentType.includes("application/json")) {
            data = await response.json();
        }
        
        if (!response.ok) {
            throw new Error((data && data.detail) ? data.detail : `Error ${response.status}`);
        }
        
        return { ok: true, data: data, response: response };
    } catch (err) {
        return { ok: false, error: err.message };
    }
}

// ==========================================
// GLOBAL STATE
// ==========================================
const store = { 
    set: (key, value) => localStorage.setItem("vs_" + key, value), 
    get: (key) => localStorage.getItem("vs_" + key) || "",
    remove: (key) => localStorage.removeItem("vs_" + key)
};

let chartObj = null; 
let benchmarkChartObj = null; 
let networkObj = null; 
let showingGraph = false;

let globalBlocks = []; 
let globalInstitutions = {}; 
let currentAnalyticsScope = "session";

let prevInstSelection = ""; 
let prevAuthSelection = ""; 
let currentDrawerMode = "";

let adminSessionActive = false; 

let memorySessionMetrics = { 
    "AUTHENTIC": 0, 
    "PROVEN_FAKE": 0, 
    "UNSIGNED": 0, 
    "REVOKED": 0, 
    "benchmarks": { "Hybrid (ECDSA + ML-DSA)": { "time": 0, "count": 0 } } 
};

// ==========================================
// AUTHENTICATION LOGIC
// ==========================================
async function checkAuthStatus() {
    const res = await safeFetch("/api/admin/me");
    adminSessionActive = res.ok;
    
    renderAdminUI();
    if (adminSessionActive) fetchLedger();
}

document.addEventListener("DOMContentLoaded", () => {
    const authDropdown = document.getElementById("authDropdown");
    if (authDropdown) {
        authDropdown.addEventListener("mousedown", () => { 
            if (currentDrawerMode === "INSTITUTION") cancelDrawer(); 
        });
    }
    checkAuthStatus();
    loadAnalytics();
});

async function handleGoogleLogin(response) {
    const fd = new FormData(); 
    fd.append("credential", response.credential);
    
    const res = await safeFetch("/api/admin/login", { method: "POST", body: fd });
    
    if (res.ok) {
        toast("Admin Clearance Granted.", "success");
        await checkAuthStatus();
    } else { 
        toast(res.error || "ACCESS DENIED: Invalid Clearance.", "error"); 
    }
}

async function logoutAdmin() {
    await safeFetch("/api/admin/logout", { method: "POST" }); 
    toast("Admin logged out.", "success");
    
    adminSessionActive = false;
    renderAdminUI();
    
    if (currentAnalyticsScope === "global") switchAnalyticsScope("session");
}

function renderAdminUI() {
    const loginScreen = document.getElementById("admin-login-screen");
    const dashboard = document.getElementById("admin-dashboard");
    const globalLock = document.getElementById("global-lock");
    const logoutBtn = document.getElementById("logoutBtn");

    if (adminSessionActive) {
        loginScreen.classList.add("hidden");
        dashboard.classList.remove("hidden");
        globalLock.classList.add("hidden");
        logoutBtn.classList.remove("hidden");
    } else {
        loginScreen.classList.remove("hidden");
        dashboard.classList.add("hidden");
        globalLock.classList.remove("hidden");
        logoutBtn.classList.add("hidden");
    }
}

// ==========================================
// UTILITIES
// ==========================================
function parseEntity(backendName) {
    if (backendName && backendName.includes("|||")) { 
        const parts = backendName.split("|||"); 
        return { inst: parts[0], post: parts[1], recipient: parts[2] || "N/A" }; 
    }
    return { inst: "Default", post: backendName || "Unknown", recipient: "N/A" };
}

function getMetrics(scope) {
    if (scope === "session") return memorySessionMetrics;
    
    if (scope === "local") {
        const defaultMetrics = '{"AUTHENTIC":0,"PROVEN_FAKE":0,"UNSIGNED":0,"REVOKED":0,"benchmarks":{"Hybrid (ECDSA + ML-DSA)":{"time":0,"count":0}}}';
        return JSON.parse(localStorage.getItem("vs_metrics_local") || defaultMetrics);
    }
    return null;
}

function recordMetric(verdict, elapsedMs) {
    ['session', 'local'].forEach(scope => {
        let m = getMetrics(scope);
        m[verdict] = (m[verdict] || 0) + 1;
        
        if (!m.benchmarks["Hybrid (ECDSA + ML-DSA)"]) {
            m.benchmarks["Hybrid (ECDSA + ML-DSA)"] = { time: 0, count: 0 };
        }
        
        m.benchmarks["Hybrid (ECDSA + ML-DSA)"].time += elapsedMs; 
        m.benchmarks["Hybrid (ECDSA + ML-DSA)"].count += 1;
        
        if (scope === "local") {
            localStorage.setItem("vs_metrics_local", JSON.stringify(m));
        }
    });
}

function updateBatchLabel(inp, id) {
    const labelEl = document.getElementById(id);
    if (inp.files.length > 1) {
        labelEl.innerText = `${inp.files.length} files queued`;
    } else {
        labelEl.innerText = inp.files[0]?.name || "Drag & drop files to batch sign";
    }
}

function updateVerifyBatchLabel(inp) { 
    const labelEl = document.getElementById("verifyLabel");
    if (inp.files.length > 1) {
        labelEl.innerText = `${inp.files.length} files selected`;
    } else {
        labelEl.innerText = inp.files[0]?.name || "Select or drop file(s)";
    }
}

function toast(msg, type = 'success') {
    const container = document.getElementById('toastContainer'); 
    if (!container) return;
    
    const el = document.createElement('div'); 
    const bgClass = type === 'success' ? 'bg-zinc-900 border-zinc-700 text-white' : 'bg-red-950 border-red-900 text-red-200';
    el.className = `px-5 py-3.5 rounded-xl border ${bgClass} shadow-2xl toast-enter text-sm backdrop-blur-md font-medium`;
    el.innerText = msg; 
    
    container.appendChild(el);
    setTimeout(() => { 
        el.style.opacity = '0'; 
        el.style.transition = 'opacity 0.3s'; 
        setTimeout(() => el.remove(), 300); 
    }, 3500);
}

function btnState(id, isLoading, originalText) { 
    const btn = document.getElementById(id); 
    if (!btn) return; 
    btn.disabled = isLoading; 
    btn.innerHTML = isLoading ? `<span class="loader"></span>` : originalText; 
    btn.style.opacity = isLoading ? "0.6" : "1"; 
}

// ==========================================
// UI NAVIGATION
// ==========================================
function switchTab(targetTab) {
    const tabs = ['public', 'admin', 'analytics'];
    
    tabs.forEach(tab => {
        const view = document.getElementById(`view-${tab}`); 
        const btn = document.getElementById(`tab-${tab}`);
        
        if (view) view.classList.toggle('hidden', tab !== targetTab);
        
        if (btn) {
            btn.className = tab === targetTab 
                ? 'px-5 py-2.5 rounded-lg text-xs font-semibold bg-zinc-800 text-white shadow-sm transition' 
                : 'px-5 py-2.5 rounded-lg text-xs font-semibold text-zinc-400 hover:text-zinc-200 transition';
        }
    });
    
    if (targetTab === 'admin' && adminSessionActive) fetchLedger();
    if (targetTab === 'analytics') loadAnalytics();
}

function switchLedgerTab(target) {
    const isFiles = target === 'files';
    
    document.getElementById('ledger-view-files').classList.toggle('hidden', !isFiles); 
    document.getElementById('ledger-view-keys').classList.toggle('hidden', isFiles);
    
    document.getElementById('tab-ledger-files').className = isFiles 
        ? 'px-4 py-1.5 rounded-lg text-xs font-semibold bg-zinc-800 text-white transition' 
        : 'px-4 py-1.5 rounded-lg text-xs font-semibold text-zinc-400 hover:text-zinc-200 transition';
        
    document.getElementById('tab-ledger-keys').className = !isFiles 
        ? 'px-4 py-1.5 rounded-lg text-xs font-semibold bg-zinc-800 text-white transition' 
        : 'px-4 py-1.5 rounded-lg text-xs font-semibold text-zinc-400 hover:text-zinc-200 transition';
        
    document.getElementById('ledgerFilterContainer').classList.toggle('hidden', !isFiles);
}

function switchAnalyticsScope(scope) {
    if (scope === "global" && !adminSessionActive) { 
        toast("Admin Clearance Required.", "error"); 
        switchTab('admin'); 
        return; 
    }
    
    currentAnalyticsScope = scope;
    const scopes = ['session', 'local', 'global'];
    
    scopes.forEach(s => {
        const btn = document.getElementById(`scope-${s}`);
        if (btn) {
            btn.className = s === scope 
                ? 'px-4 py-1.5 rounded-lg text-xs font-semibold bg-zinc-800 text-white transition' 
                : 'px-4 py-1.5 rounded-lg text-xs font-semibold text-zinc-400 hover:text-zinc-200 transition';
        }
    });
    
    loadAnalytics();
}

// Map drag and drop events for file inputs
['verifyDrop', 'signDrop'].forEach(id => { 
    const el = document.getElementById(id); 
    if (el) { 
        el.ondragover = e => { 
            e.preventDefault(); 
            el.classList.add('drag-active'); 
        }; 
        el.ondragleave = el.ondrop = () => {
            el.classList.remove('drag-active'); 
        };
    } 
});

// ==========================================
// INSTITUTIONAL FORMS
// ==========================================
function handleInstChange(val) {
    const authDropdown = document.getElementById("authDropdown"); 
    
    if (val === "ADD_NEW_INST") {
        currentDrawerMode = "INSTITUTION"; 
        document.getElementById("drawerTitle").innerText = "Create New Institution (Main House)";
        
        document.getElementById("drawerInst").classList.remove("hidden"); 
        document.getElementById("drawerInst").classList.add("flex");
        
        document.getElementById("drawerAuth").classList.add("hidden"); 
        document.getElementById("drawerAuth").classList.remove("flex");
        
        document.getElementById("newEntryDrawer").classList.remove("hidden"); 
        document.getElementById("newEntryDrawer").classList.add("flex");
        
        authDropdown.disabled = false; 
        authDropdown.innerHTML = `<option value="" disabled selected>-- Choose Post --</option>`; 
        return;
    }

    prevInstSelection = val; 
    hideDrawerUI(); 
    authDropdown.disabled = false;
    
    let authHTML = `<option value="" disabled selected>-- Choose Post (Resident) --</option>`;
    
    Object.values(globalInstitutions).forEach(i => {
        if (!i.is_revoked) { 
            const parsed = parseEntity(i.name); 
            if (parsed.inst === val) {
                authHTML += `<option value="${i.id}">${parsed.post} - ${parsed.recipient}</option>`; 
            }
        }
    });
    
    authHTML += `<option value="ADD_NEW_AUTH" class="font-bold text-emerald-400">+ Add New Post to ${val}...</option>`; 
    authDropdown.innerHTML = authHTML; 
    prevAuthSelection = ""; 
}

async function handleAuthChange(val) {
    const instDropdown = document.getElementById("instDropdown");
    
    if (currentDrawerMode === "INSTITUTION") {
        cancelDrawer();
    }
    
    if (val === "ADD_NEW_AUTH") {
        currentDrawerMode = "AUTHORITY"; 
        document.getElementById("drawerTitle").innerText = `Issue Key for Post under: ${instDropdown.value}`;
        
        document.getElementById("drawerAuth").classList.remove("hidden"); 
        document.getElementById("drawerAuth").classList.add("flex");
        
        document.getElementById("drawerInst").classList.add("hidden"); 
        document.getElementById("drawerInst").classList.remove("flex");
        
        document.getElementById("newEntryDrawer").classList.remove("hidden"); 
        document.getElementById("newEntryDrawer").classList.add("flex");
        return;
    }
    
    prevAuthSelection = val; 
    hideDrawerUI();
    toast("Authority Linked. KMS Vault Ready for Signing.", "success");
}

function hideDrawerUI() {
    const drawer = document.getElementById("newEntryDrawer"); 
    drawer.classList.add("hidden"); 
    drawer.classList.remove("flex");
    
    document.getElementById("drawerInst").classList.add("hidden"); 
    document.getElementById("drawerInst").classList.remove("flex");
    
    document.getElementById("drawerAuth").classList.add("hidden"); 
    document.getElementById("drawerAuth").classList.remove("flex");
    
    document.getElementById("regInstName").value = ""; 
    document.getElementById("regAuthRecipient").value = ""; 
    document.getElementById("regAuthTitle").value = "";
}

function cancelDrawer() {
    hideDrawerUI(); 
    const instDropdown = document.getElementById("instDropdown"); 
    const authDropdown = document.getElementById("authDropdown");

    if (currentDrawerMode === "INSTITUTION") {
        instDropdown.value = prevInstSelection || "";
        
        if (!prevInstSelection || prevInstSelection === "ADD_NEW_INST") { 
            authDropdown.disabled = true; 
            authDropdown.innerHTML = `<option value="" disabled selected>-- Choose Post --</option>`; 
        } else {
            authDropdown.disabled = false; 
            let authHTML = `<option value="" disabled selected>-- Choose Post --</option>`;
            
            Object.values(globalInstitutions).forEach(i => { 
                if (!i.is_revoked) { 
                    const p = parseEntity(i.name); 
                    if (p.inst === prevInstSelection) {
                        authHTML += `<option value="${i.id}">${p.post} - ${p.recipient}</option>`; 
                    }
                } 
            });
            
            authHTML += `<option value="ADD_NEW_AUTH" class="font-bold text-emerald-400">+ Add New Post...</option>`; 
            authDropdown.innerHTML = authHTML; 
            authDropdown.value = prevAuthSelection || "";
        }
    } else if (currentDrawerMode === "AUTHORITY") { 
        authDropdown.value = prevAuthSelection || ""; 
    }
    
    currentDrawerMode = "";
}

function submitNewInstitution() {
    const instName = document.getElementById('regInstName').value.trim(); 
    if (!instName) return toast('Provide Name', 'error');
    
    let customList = JSON.parse(localStorage.getItem('vs_custom_inst') || '[]');
    
    if (!customList.includes(instName)) { 
        customList.push(instName); 
        localStorage.setItem('vs_custom_inst', JSON.stringify(customList)); 
    }
    
    toast('Institution Created.'); 
    hideDrawerUI(); 
    
    fetchLedger().then(() => { 
        document.getElementById("instDropdown").value = instName; 
        handleInstChange(instName); 
    });
}

async function submitNewAuthority() {
    const recipient = document.getElementById("regAuthRecipient").value.trim(); 
    const postTitle = document.getElementById("regAuthTitle").value.trim(); 
    const instName = document.getElementById("instDropdown").value;
    
    if (!recipient || !postTitle || !instName || instName === "ADD_NEW_INST") {
        return toast("Provide details.", "error");
    }
    
    // Auto-generate identifier
    const genId = recipient.replace(/\s+/g, '-').toUpperCase() + "-" + Math.floor(Math.random() * 1000);
    const fd = new FormData(); 
    fd.append("institution_id", genId); 
    fd.append("name", `${instName}|||${postTitle}|||${recipient}`);
    
    const res = await safeFetch("/api/register", { method: "POST", body: fd });
    
    if (res.ok) {
        toast("Key generated."); 
        hideDrawerUI(); 
        await fetchLedger(); 
        
        setTimeout(() => { 
            document.getElementById("instDropdown").value = instName; 
            handleInstChange(instName); 
            
            document.getElementById("authDropdown").value = res.data.institution_id; 
            handleAuthChange(res.data.institution_id); 
        }, 100);
    } else {
        toast(res.error, "error");
    }
}

// ==========================================
// LEDGER OPERATIONS
// ==========================================
function updateFilterPosts() {
    const inst = document.getElementById("filterInst").value; 
    const postFilter = document.getElementById("filterPost"); 
    let prevPost = postFilter.value;
    
    let html = `<option value="ALL">All Posts</option>`;
    
    Object.values(globalInstitutions).forEach(i => { 
        let parsed = parseEntity(i.name); 
        if (inst === "ALL" || parsed.inst === inst) {
            html += `<option value="${i.id}">${parsed.post}</option>`; 
        }
    });
    
    postFilter.innerHTML = html; 
    
    if (Array.from(postFilter.options).some(o => o.value === prevPost)) {
        postFilter.value = prevPost;
    } else {
        postFilter.value = "ALL";
    }
}

function applyFilters() {
    const inst = document.getElementById("filterInst").value; 
    const post = document.getElementById("filterPost").value;
    
    let filtered = globalBlocks.filter(b => { 
        let p = parseEntity(b.inst_name); 
        return (inst === "ALL" || p.inst === inst) && (post === "ALL" || b.inst_id === post); 
    });
    
    document.getElementById("ledgerCount").innerText = `${filtered.length} RECORDS`;
    
    const tbody = document.getElementById("ledgerBody");
    
    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="py-6 text-center text-zinc-500">No records found.</td></tr>';
        return;
    }
    
    tbody.innerHTML = filtered.map(b => {
        let p = parseEntity(b.inst_name); 
        let badge = b.is_revoked 
            ? '<span class="text-red-400 font-bold">REVOKED</span>' 
            : '<span class="text-emerald-400 font-bold">ANCHORED</span>';
            
        const ipfsLink = b.ipfs_cid && !b.ipfs_cid.includes("CLIENT") 
            ? `<a href="https://ipfs.io/ipfs/${b.ipfs_cid}" target="_blank" class="text-indigo-400">IPFS</a>` 
            : 'Local';
            
        return `
            <tr class="hover:bg-zinc-800/30 transition">
                <td class="py-3.5 text-zinc-400 font-mono text-[11px]">${b.timestamp.replace(" UTC", "")}</td>
                <td class="py-3.5 text-zinc-100 font-semibold">${p.inst}</td>
                <td class="py-3.5 text-zinc-300 font-mono">${p.post}</td>
                <td class="py-3.5 text-indigo-300 font-medium">${p.recipient}</td>
                <td class="py-3.5 text-zinc-400 font-mono text-sm">${b.filename}</td>
                <td class="py-3.5 font-mono text-xs">${ipfsLink}</td>
                <td class="py-3.5 text-[11px]">${badge}</td>
            </tr>
        `;
    }).join("");
}

function toggleLedgerView() {
    showingGraph = !showingGraph; 
    const btn = document.getElementById("viewToggleBtn"); 
    const table = document.getElementById("ledgerTableContainer"); 
    const graph = document.getElementById("ledgerGraphContainer");
    
    if (showingGraph) { 
        btn.innerText = "Show Table View"; 
        table.classList.add("hidden"); 
        graph.classList.remove("hidden"); 
        loadNetworkGraph(); 
    } else { 
        btn.innerText = "Show Dependency Map"; 
        graph.classList.add("hidden"); 
        table.classList.remove("hidden"); 
    }
}

async function fetchLedger() {
    const res = await safeFetch("/api/ledger"); 
    if (!res.ok) return; 
    
    globalBlocks = res.data.blocks || []; 
    globalInstitutions = res.data.institutions || {};
    
    const rbSelect = document.getElementById("rollbackSelect"); 
    let rbHTML = `<option value="">Restore Point...</option>`;
    
    // Sort unique timestamps dynamically for rollback dropdown
    const uniqueTimestamps = [...new Set(globalBlocks.map(b => b.timestamp))];
    uniqueTimestamps.sort().reverse().slice(0, 15).forEach(ts => { 
        rbHTML += `<option value="${ts}">${ts.replace(" UTC", "")}</option>`; 
    });
    
    if (rbSelect) rbSelect.innerHTML = rbHTML;

    let instSet = new Set(JSON.parse(localStorage.getItem('vs_custom_inst') || '[]')); 
    Object.values(globalInstitutions).forEach(i => {
        instSet.add(parseEntity(i.name).inst);
    });
    
    const instDropdown = document.getElementById("instDropdown"); 
    let instHTML = `<option value="" disabled ${!prevInstSelection ? 'selected' : ''}>-- Choose Institution --</option>`;
    
    instSet.forEach(instName => { 
        instHTML += `<option value="${instName}" ${prevInstSelection === instName ? 'selected' : ''}>${instName}</option>`; 
    });
    
    instHTML += `<option value="ADD_NEW_INST" class="font-bold text-emerald-400">+ Add New Institution...</option>`; 
    instDropdown.innerHTML = instHTML;

    const filterInst = document.getElementById("filterInst"); 
    let fHTML = `<option value="ALL">All Institutions</option>`;
    
    instSet.forEach(n => {
        fHTML += `<option value="${n}">${n}</option>`;
    }); 
    
    filterInst.innerHTML = fHTML; 
    updateFilterPosts(); 

    const keyBody = document.getElementById("keyLedgerBody");
    
    if (Object.values(globalInstitutions).length === 0) {
        keyBody.innerHTML = '<tr><td colspan="6" class="py-6 text-center text-zinc-500">No keys.</td></tr>';
    } else {
        keyBody.innerHTML = Object.values(globalInstitutions).map(i => {
            const p = parseEntity(i.name);
            const statusBadge = i.is_revoked 
                ? `<span class="text-red-400 font-bold">${i.revoked_at.replace(" UTC", "")}</span>` 
                : '<span class="text-emerald-400 font-bold">Active</span>';
            
            const revokeBtn = !i.is_revoked 
                ? `<button onclick="handleRevoke('${i.id}')" class="text-red-400 text-xs px-3 py-1.5 rounded-lg">Revoke</button>` 
                : '';
                
            return `
                <tr class="hover:bg-zinc-800/30 transition">
                    <td class="py-3.5 text-zinc-100 font-semibold">${p.inst}</td>
                    <td class="py-3.5 text-zinc-300 font-mono">${p.post}</td>
                    <td class="py-3.5 text-indigo-300 font-medium">${p.recipient}</td>
                    <td class="py-3.5 text-zinc-400 font-mono text-[11px]">${i.registered_at.replace(" UTC", "")}</td>
                    <td class="py-3.5 font-mono text-[11px]">${statusBadge}</td>
                    <td class="py-3.5">
                        <div class="flex gap-2">
                            ${revokeBtn}
                        </div>
                    </td>
                </tr>
            `;
        }).join("");
    }

    applyFilters(); 
    
    if (showingGraph) loadNetworkGraph();
}

// Initialize network graph with fetched ledger data
async function loadNetworkGraph() {
    const res = await safeFetch("/api/network");
    if (!res.ok) return;
    
    const nodes = new vis.DataSet((res.data.nodes || []).map(n => {
        let p = parseEntity(n.label);
        
        if (n.group === 'authority') {
            return { 
                id: n.id, 
                label: p.post + "\n(" + p.recipient + ")", 
                shape: 'dot', 
                size: 40, 
                color: { 
                    background: n.is_revoked ? '#ef4444' : '#10b981', 
                    border: '#27272a' 
                }, 
                font: { color: '#e4e4e7', size: 24, face: 'monospace' } 
            };
        }
        
        return { 
            id: n.id, 
            label: n.is_compromised ? (n.label || "") + "\n(EXPOSED)" : (n.label || ""), 
            shape: 'box', 
            color: { 
                background: n.is_revoked ? '#ef4444' : '#52525b', 
                border: '#27272a' 
            }, 
            font: { color: '#e4e4e7', size: 20, face: 'monospace' } 
        };
    }));
    
    const edges = new vis.DataSet(res.data.edges || []);
    
    if (networkObj) networkObj.destroy();
    
    networkObj = new vis.Network(
        document.getElementById('ledgerGraphContainer'), 
        { nodes, edges }, 
        { 
            layout: { 
                hierarchical: { enabled: true, direction: "LR", levelSeparation: 450 } 
            }, 
            physics: false, 
            edges: { color: '#71717a', width: 3, smooth: { type: 'cubicBezier' } } 
        }
    );
}

// ==========================================
// SYSTEM ACTIONS & ANALYTICS
// ==========================================
async function executeDDay() {
    toast("D-DAY INITIATED.", "error");
    
    const res = await safeFetch("/api/dday", { method: "POST" }); 
    
    if (res.ok) {
        if (adminSessionActive) fetchLedger(); 
        loadAnalytics();
    } else {
        toast(res.error, "error");
    }
}

async function executeRollback() {
    const targetTS = document.getElementById("rollbackSelect").value; 
    
    if (!targetTS) {
        return toast("Select a point.", "error");
    }
    
    const fd = new FormData(); 
    fd.append("target_timestamp", targetTS);
    
    const res = await safeFetch("/api/rollback", { method: "POST", body: fd });
    
    if (res.ok) { 
        toast(`Restore Complete to ${targetTS.replace(" UTC", "")}`); 
        if (adminSessionActive) fetchLedger(); 
        loadAnalytics(); 
    } else {
        toast(res.error, "error");
    }
}

async function loadAnalytics() {
    let stats = { "AUTHENTIC": 0, "PROVEN_FAKE": 0, "UNSIGNED": 0, "REVOKED": 0, "benchmarks": {} };
    
    if (currentAnalyticsScope === "global") { 
        const res = await safeFetch("/api/analytics");
        if (res.ok) stats = res.data.stats || stats; 
    } else { 
        const m = getMetrics(currentAnalyticsScope); 
        stats.AUTHENTIC = m.AUTHENTIC || 0; 
        stats.PROVEN_FAKE = m.PROVEN_FAKE || 0; 
        stats.UNSIGNED = m.UNSIGNED || 0; 
        stats.REVOKED = m.REVOKED || 0; 
        
        for (const [algo, data] of Object.entries(m.benchmarks || {})) {
            if (data.count > 0) {
                stats.benchmarks[algo] = { avg_time_ms: Math.round((data.time / data.count) * 100) / 100 };
            }
        }
    }

    document.getElementById("stat-auth").innerText = stats.AUTHENTIC || 0; 
    document.getElementById("stat-fake").innerText = stats.PROVEN_FAKE || 0;
    document.getElementById("stat-unsigned").innerText = stats.UNSIGNED || 0; 
    document.getElementById("stat-revoked").innerText = stats.REVOKED || 0;
    
    if (chartObj) chartObj.destroy();
    
    chartObj = new Chart(document.getElementById('threatChart').getContext('2d'), { 
        type: 'doughnut', 
        data: { 
            labels: ['Authentic', 'Forgeries', 'Unsigned', 'Revoked'], 
            datasets: [{ 
                data: [stats.AUTHENTIC, stats.PROVEN_FAKE, stats.UNSIGNED, stats.REVOKED], 
                backgroundColor: ['#10b981', '#ef4444', '#71717a', '#f43f5e'], 
                borderWidth: 0 
            }] 
        }, 
        options: { 
            cutout: '75%', 
            plugins: { legend: { display: false } } 
        } 
    });

    // Handle Benchmarking charts
    const benchCanvas = document.getElementById('benchmarkChart');
    if (benchCanvas) {
        if (benchmarkChartObj) benchmarkChartObj.destroy();
        
        const bLabels = []; 
        const bData = [];
        
        if (stats.benchmarks) {
            for (const [algo, dataStats] of Object.entries(stats.benchmarks)) { 
                bLabels.push(algo); 
                bData.push(dataStats.avg_time_ms); 
            }
        }
        
        benchmarkChartObj = new Chart(benchCanvas.getContext('2d'), {
            type: 'bar',
            data: { 
                labels: bLabels.length ? bLabels : ["Hybrid Engine"], 
                datasets: [{ 
                    label: 'Avg Execution Time (ms)', 
                    data: bData.length ? bData : [0], 
                    backgroundColor: ['#8b5cf6'], 
                    borderRadius: 6 
                }] 
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false, 
                scales: { 
                    y: { 
                        beginAtZero: true, 
                        grid: { color: 'rgba(255,255,255,0.05)' }, 
                        ticks: { color: '#a1a1aa' } 
                    }, 
                    x: { 
                        grid: { display: false }, 
                        ticks: { color: '#a1a1aa' } 
                    } 
                }, 
                plugins: { legend: { display: false } } 
            }
        });
    }
}

async function handleSign() {
    const files = document.getElementById("signInput").files; 
    const authSel = document.getElementById("authDropdown").value; 
    
    // Only validating that files and an institution exist. The key is retrieved server-side.
    if (!files.length || !authSel || authSel.startsWith("ADD_NEW")) {
        return toast("Select a valid Post and attach files.", "error");
    }
    
    btnState('signBtn', true, 'Sign & Anchor to IPFS');
    
    const fd = new FormData(); 
    fd.append("institution_id", authSel); 
    
    for (let i = 0; i < files.length; i++) {
        fd.append("files", files[i]);
    }
    
    try {
        const res = await fetch("/api/sign", { 
            method: "POST", 
            body: fd, 
            credentials: "include" 
        });
        
        if (res.status === 429) { 
            toast("Rate limit exceeded. Slow down.", "error"); 
            return; 
        }
        
        if (res.ok) {
            const blob = await res.blob(); 
            const blobUrl = window.URL.createObjectURL(blob); 
            const a = document.createElement("a"); 
            
            a.href = blobUrl; 
            a.download = files.length > 1 
                ? "signed_batch.zip" 
                : `signed_${files[0].name}`;
                
            document.body.appendChild(a); 
            a.click(); 
            a.remove(); 
            window.URL.revokeObjectURL(blobUrl); 
            
            toast("File Downloaded."); 
            fetchLedger();
        } else {
            let err = "Failed";
            try { 
                const errorData = await res.json();
                err = errorData.detail; 
            } catch(e) {}
            toast(err, "error");
        }
    } catch(e) { 
        toast("Network error.", "error"); 
    } finally { 
        btnState('signBtn', false, 'Sign & Anchor to IPFS'); 
    }
}

async function handleVerify() {
    const rawFiles = document.getElementById("verifyInput").files; 
    if (!rawFiles.length) return toast("Select file(s).", "error");
    
    btnState('verifyBtn', true, 'Checking Authenticity...'); 
    
    const resultBox = document.getElementById("verifyResult");
    resultBox.innerHTML = ""; 
    resultBox.classList.remove("hidden");
    
    let filesToVerify = [];
    
    for (let f of rawFiles) {
        if (f.name.toLowerCase().endsWith(".zip")) {
            try { 
                const zip = await JSZip.loadAsync(f); 
                for (let filename of Object.keys(zip.files)) { 
                    if (!zip.files[filename].dir) {
                        filesToVerify.push({ blob: await zip.files[filename].async("blob"), name: filename }); 
                    }
                } 
            } catch (e) { 
                filesToVerify.push({ blob: f, name: f.name }); 
            }
        } else {
            filesToVerify.push({ blob: f, name: f.name });
        }
    }
    
    for (let item of filesToVerify) {
        const t0 = performance.now(); 
        const fd = new FormData(); 
        fd.append("file", item.blob, item.name); 
        fd.append("filename", item.name);
        
        const res = await safeFetch("/api/verify", { method: "POST", body: fd });
        
        if (res.ok) {
            const data = res.data;
            recordMetric(data.verdict, Math.round(performance.now() - t0));
            
            const styleMap = { 
                'AUTHENTIC': 'bg-emerald-950/40 border-emerald-500/50 text-emerald-400', 
                'PROVEN_FAKE': 'bg-red-950/40 border-red-500/50 text-red-400', 
                'REVOKED': 'bg-rose-950/40 border-rose-500/50 text-rose-400', 
                'UNSIGNED': 'bg-zinc-900 border-zinc-700 text-zinc-300' 
            };
            
            const displayVerdict = data.verdict === 'PROVEN_FAKE' ? 'FORGERY DETECTED' : data.verdict;
            
            const row = document.createElement("div"); 
            row.className = `p-5 rounded-2xl border text-sm ${styleMap[data.verdict]}`;
            row.innerHTML = `
                <div class="flex justify-between mb-1">
                    <span class="font-bold">${displayVerdict}</span>
                    <span class="text-xs opacity-75">${item.name}</span>
                </div>
                <div class="text-xs">${data.message}</div>
                <div class="mt-2 text-[10px] font-mono opacity-50">SHA-256: ${data.hash}</div>
            `;
            
            resultBox.appendChild(row);
        } else {
            toast(res.error, "error");
            break; 
        }
    }
    
    loadAnalytics(); 
    btnState('verifyBtn', false, 'Check Authenticity');
}

async function handleRevoke(id) {
    if (!confirm(`Revoke ${id}?`)) return;
    
    const fd = new FormData(); 
    fd.append("institution_id", id);
    
    const res = await safeFetch("/api/revoke", { method: "POST", body: fd });
    
    if (res.ok) { 
        toast(`Revoked.`, 'error'); 
        fetchLedger(); 
    } else { 
        toast(res.error, 'error'); 
    }
}