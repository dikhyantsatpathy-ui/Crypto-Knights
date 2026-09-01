(() => {
    // ============================================================
    // API WRAPPER
    // ------------------------------------------------------------
    // Every authenticated request carries the HttpOnly session cookie.
    // Non-2xx responses become a structured {ok:false,error} so callers
    // just check `res.ok` instead of repeating try/catch everywhere.
    // ============================================================
    async function safeFetch(url, options = {}) {
        options.credentials = "include";
        try {
            const response = await fetch(url, options);
            if (response.status === 429) throw new Error("Rate limit exceeded. Please wait.");

            let data = null;
            // Calling .blob() AFTER .json() on the same body is illegal — the
            // first read consumes it and the second rejects. Attachments (signed
            // files, broadcast receipts) carry a Content-Disposition header, so
            // skip the JSON pre-read and let the caller consume the raw bytes.
            // Error responses (HTTPException JSON, no Content-Disposition) still
            // parse normally and surface as {ok:false, error}.
            const isAttachment = (response.headers.get("content-disposition") || "").includes("attachment");
            if (!isAttachment && (response.headers.get("content-type") || "").includes("application/json")) {
                data = await response.json();
            }
            if (!response.ok) throw new Error(data && data.detail ? data.detail : `Error ${response.status}`);

            // `response` is kept too: binary endpoints (signed files) read their
            // body as a blob *after* this wrapper returns, so we never pre-consume it.
            return { ok: true, data, response };
        } catch (err) {
            return { ok: false, error: err.message };
        }
    }

    // ============================================================
    // GLOBAL STATE
    // ============================================================
    let globalBlocks = [];
    let globalSigners = {};
    let currentAnalyticsScope = "session";
    let adminSessionActive = false;
    let isSuperAdmin = false;
    let currentUserEmail = "";
    let verifyInputMode = "file";
    let showingGraph = false;
    let currentRevokeTarget = null;
    let isReinstating = false;
    let isSettingPin = false;
    let isDoubleWarningPhase = false;
    let currentUserDesignation = "";
    let currentUserInstitution = "";
    let currentRoleApproved = false;

    let networkObj = null;
    let threatChartObj = null;

    const memorySessionMetrics = { "AUTHENTIC": 0, "PROVEN_FAKE": 0, "UNSIGNED": 0, "REVOKED": 0 };

    // Analytics keep two scopes: this tab's memory and everything stored in
    // localStorage under a fixed key (shared across tabs, survives reloads).
    const LOCAL_METRICS_KEY = "nocap_metrics_local";
    const EMPTY_METRICS = { "AUTHENTIC": 0, "PROVEN_FAKE": 0, "UNSIGNED": 0, "REVOKED": 0 };

    function readLocalMetrics() {
        try {
            return { ...EMPTY_METRICS, ...JSON.parse(localStorage.getItem(LOCAL_METRICS_KEY) || "{}") };
        } catch (e) {
            return { ...EMPTY_METRICS };
        }
    }

    function recordMetric(verdict) {
        memorySessionMetrics[verdict] = (memorySessionMetrics[verdict] || 0) + 1;
        const local = readLocalMetrics();
        local[verdict] += 1;
        localStorage.setItem(LOCAL_METRICS_KEY, JSON.stringify(local));
    }

    // ============================================================
    // TINY DOM / UI HELPERS
    // ============================================================
    // One selector alias keeps every lookup on one line and greppable.
    const $ = (id) => document.getElementById(id);

    // The loader ring used by every busy button lives here once, instead of
    // being copy-pasted into each handler.
    const SPINNER = '<span style="display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,0.35);border-top-color:#fff;border-radius:50%;animation:spin 0.7s linear infinite"></span>';

    // busy() remembers a button's normal label so idle() can put it back —
    // the old code re-typed those button labels in every success/failure path.
    function busy(btn, text) {
        if (!btn) return;
        btn.dataset.restore = btn.innerHTML;
        btn.disabled = true;
        if (text) btn.innerHTML = `${SPINNER}${text}`;
    }
    function idle(btn) {
        if (!btn) return;
        btn.disabled = false;
        btn.innerHTML = btn.dataset.restore || btn.innerHTML;
    }

    // Fires a blob download through a transient <a> element — shared by the
    // "sign media" and "sign broadcast" handlers.
    function downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    }

    // Escapes arbitrary text before it lands in innerHTML. Server data (names,
    // roles, messages) flows through this so it can never break out as markup.
    const esc = (s) => String(s == null ? "" : s)
        .replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

    const shortHash = (h) => (h && h.length > 22) ? `${h.slice(0, 10)}…${h.slice(-8)}` : (h || "—");

    window.copyHash = (el, value) => {
        if (navigator.clipboard) navigator.clipboard.writeText(value);
        toast("Digest copied to clipboard.", "success");
    };

    // wireDropzone() standardises the repeated drag-and-drop behaviour: hover
    // glow while dragging, and a label that reflects the chosen file(s).
    function setFileLabel(label, files) {
        if (!label || !files.length) return;
        label.textContent = files.length > 1 ? `${files.length} files selected` : files[0].name;
    }
    function wireDropzone(zone, input, label) {
        if (!zone || !input) return;
        ["dragenter", "dragover"].forEach(ev => zone.addEventListener(ev, (e) => {
            e.preventDefault();
            zone.classList.add("drag-active");
        }));
        ["dragleave", "drop"].forEach(ev => zone.addEventListener(ev, (e) => {
            e.preventDefault();
            zone.classList.remove("drag-active");
        }));
        zone.addEventListener("drop", (e) => {
            if (e.dataTransfer.files.length) {
                input.files = e.dataTransfer.files;
                setFileLabel(label, input.files);
            }
        });
        input.addEventListener("change", () => setFileLabel(label, input.files));
    }

    // ============================================================
    // TOASTS
    // ============================================================
    const toastWrap = $("toastWrap");
    const icons = {
        success: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
        error:   '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
        warn:    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/></svg>',
        info:    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>',
    };

    window.toast = (msg, kind = "info") => {
        const el = document.createElement("div");
        el.className = `toast ${kind}`;
        el.innerHTML = `<div class="toast-icon">${icons[kind] || icons.info}</div><div>${msg}</div>`;
        toastWrap.appendChild(el);
        setTimeout(() => { el.style.opacity = "0"; el.style.transform = "translateY(10px)"; }, 3200);
        setTimeout(() => el.remove(), 3700);
    };

    // ============================================================
    // HERO COUNTERS
    // ============================================================
    // The numbers on the landing page tick up with an eased animation; when the
    // public /api/stats endpoint answers we re-run the same animation on real
    // counts, otherwise the baked-in demo numbers stay.
    const counters = document.querySelectorAll("[data-counter]");
    const animateCounter = (el) => {
        const target = parseFloat(el.dataset.counter);
        const suffix = el.dataset.suffix || "";
        const isFloat = target % 1 !== 0;
        const duration = 1500;
        const start = performance.now();
        const step = (now) => {
            const p = Math.min((now - start) / duration, 1);
            const eased = 1 - Math.pow(1 - p, 3);
            const val = target * eased;
            el.textContent = (isFloat ? val.toFixed(2) : Math.floor(val).toLocaleString()) + suffix;
            if (p < 1) requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
    };
    counters.forEach(animateCounter);

    async function fetchPublicStats() {
        const res = await safeFetch("/api/stats");
        if (!res.ok) return;
        const els = document.querySelectorAll("[data-counter]");
        if (els[0]) els[0].dataset.counter = res.data.signed_docs;
        if (els[1]) els[1].dataset.counter = res.data.trusted_issuers;
        els.forEach(animateCounter);
    }

    // ============================================================
    // VIEW SWITCHING (SINGLE-PAGE NAV)
    // ============================================================
    const views = document.querySelectorAll(".view");
    const navBtns = document.querySelectorAll(".nav-link:not(#logoutBtn)");
    navBtns.forEach((btn) => {
        btn.addEventListener("click", () => {
            navBtns.forEach((b) => b.classList.remove("active"));
            btn.classList.add("active");
            views.forEach((v) => v.classList.add("hidden"));
            const view = $("view-" + btn.dataset.view);
            if (view) view.classList.remove("hidden");

            // Expensive tabs render lazily — only when they actually open.
            if (btn.dataset.view === "admin" && adminSessionActive) fetchLedger();
            if (btn.dataset.view === "analytics") setTimeout(loadAnalytics, 50); // let the panel size up first
        });
    });

    // Exposed on window because the HTML buttons use inline onclick=.
    window.switchVerifyMode = (mode) => {
        verifyInputMode = mode;
        const isFile = mode === "file";
        $("verifyFileContainer").classList.toggle("hidden", !isFile);
        $("verifyTextContainer").classList.toggle("hidden", isFile);
        $("vbtn-file").className = isFile ? "toggle-btn active" : "toggle-btn";
        $("vbtn-text").className = !isFile ? "toggle-btn active" : "toggle-btn";
    };

    // ============================================================
    // AUTHENTICATION (GOOGLE OIDC + SESSION COOKIE)
    // ============================================================
    // Element refs that change identity/role appearance get queried once.
    const roleBadge = $("signerRoleBadge");
    const roleLabel = $("signerRoleLabel");
    const roleMeta = $("signerRoleMeta");
    const signBtnEl = $("signBtn");

    async function checkAuthStatus() {
        const res = await safeFetch("/api/admin/me");
        adminSessionActive = res.ok;

        if (adminSessionActive) {
            isSuperAdmin = res.data.is_super_admin;
            currentUserEmail = res.data.admin;
            currentUserDesignation = res.data.designation || "";
            currentUserInstitution = res.data.institution || "";
            currentRoleApproved = !res.data.pending_approval;
        } else {
            isSuperAdmin = false;
            currentRoleApproved = false;
            currentUserDesignation = "";
            currentUserInstitution = "";
        }

        $("admin-login-screen").classList.toggle("hidden", adminSessionActive);
        $("admin-dashboard").classList.toggle("hidden", !adminSessionActive);
        $("logoutBtn").classList.toggle("hidden", !adminSessionActive);

        renderSignerRoleBadge();
        if (adminSessionActive) fetchLedger();
        loadBroadcasts();
    }

    // The badge above the signing panel is the anti-impersonation gate: until a
    // super admin assigns the post + institution, it stays amber and blocks signing.
    function renderSignerRoleBadge() {
        if (!roleBadge) return;
        if (currentRoleApproved) {
            roleLabel.textContent = `${currentUserDesignation} · ${currentUserInstitution}`;
            roleMeta.textContent = `Verified signer · ${currentUserEmail}`;
            roleBadge.style.borderColor = "rgba(34,227,164,0.3)";
            roleBadge.style.background = "rgba(34,227,164,0.08)";
            roleBadge.style.color = "var(--emerald)";
            if (signBtnEl) signBtnEl.disabled = false;
        } else {
            roleLabel.textContent = "Pending Super-Admin Approval";
            roleMeta.textContent = "Signing is blocked until an administrator approves your post & institution.";
            roleBadge.style.borderColor = "rgba(255,184,76,0.35)";
            roleBadge.style.background = "rgba(255,184,76,0.08)";
            roleBadge.style.color = "var(--amber)";
            if (signBtnEl) signBtnEl.disabled = true;
        }
    }

    // Registered as the GSI `data-callback` in index.html.
    window.handleGoogleLogin = async (response) => {
        const fd = new FormData();
        fd.append("credential", response.credential);
        const res = await safeFetch("/api/admin/login", { method: "POST", body: fd });
        if (res.ok) {
            toast("Admin Clearance Granted.", "success");
            await checkAuthStatus();
        } else {
            toast(res.error || "ACCESS DENIED: Invalid Clearance.", "error");
        }
    };

    $("logoutBtn").addEventListener("click", async () => {
        await safeFetch("/api/admin/logout", { method: "POST" });
        toast("Admin logged out.", "success");
        await checkAuthStatus();
        // A logged-out session can't interrogate the global analytics scope.
        if (currentAnalyticsScope === "global") {
            $("analyticsScope").value = "session";
            currentAnalyticsScope = "session";
        }
    });

    // ============================================================
    // PUBLIC VERIFICATION
    // ============================================================
    const verifyDrop = $("verifyDrop");
    const verifyInput = $("verifyInput");
    const verifyLabel = $("verifyLabel");
    const verifyBtn = $("verifyBtn");
    const verifyResult = $("verifyResult");

    wireDropzone(verifyDrop, verifyInput, verifyLabel);

    window.handleVerify = async () => {
        verifyResult.innerHTML = "";
        verifyResult.classList.remove("hidden");

        // --- Emergency text path: the raw string is hashed & checked server-side.
        if (verifyInputMode === "text") {
            const body = $("verifyTextInput").value.trim();
            if (!body) return toast("Paste emergency text message to verify.", "warn");

            const fd = new FormData();
            fd.append("raw_text", body);
            busy(verifyBtn, "Analyzing Digest...");
            const res = await safeFetch("/api/verify", { method: "POST", body: fd });
            renderVerificationRow(res, "Emergency_Notice.txt", null);
            idle(verifyBtn);
            return;
        }

        // --- File path: a .zip is unpacked in the browser so each entry is
        // verified individually (and its media previewed) rather than as one blob.
        const files = verifyInput.files;
        if (!files.length) return toast("Select file(s).", "warn");

        busy(verifyBtn, "Verifying…");
        const items = [];
        for (const f of files) {
            if (f.name.toLowerCase().endsWith(".zip")) {
                try {
                    const zip = await JSZip.loadAsync(f);
                    for (const inner of Object.keys(zip.files)) {
                        if (!zip.files[inner].dir) items.push({ blob: await zip.files[inner].async("blob"), name: inner });
                    }
                } catch (e) {
                    // Corrupt archive? Fall back to hashing the zip itself.
                    items.push({ blob: f, name: f.name });
                }
            } else {
                items.push({ blob: f, name: f.name });
            }
        }

        for (const item of items) {
            const fd = new FormData();
            fd.append("file", item.blob, item.name);
            fd.append("filename", item.name);
            const res = await safeFetch("/api/verify", { method: "POST", body: fd });
            renderVerificationRow(res, item.name, item.blob);
        }
        idle(verifyBtn);
    };

    // One truth-table per verdict keeps the card rendering a pure lookup instead
    // of an if/else chain. `note` is overridden by the server's own message.
    const VERDICT_PROFILES = {
        AUTHENTIC: {
            banner: "auth", className: "success", label: "AUTHENTIC · Signature Verified", color: "#22e3a4",
            note: "Cryptographic signature is valid, embedded metadata traps are intact, and the anchor matches the on-chain record."
        },
        PROVEN_FAKE: {
            banner: "fake", className: "error", label: "FORGERY DETECTED · Forensic Trap Triggered", color: "#fb3a6b",
            note: "Embedded NS2H-forensic traps were wounded or missing, meaning the file was altered after signing."
        },
        REVOKED: {
            banner: "rev", className: "warn", label: "REVOKED · Signer Key Withdrawn", color: "#ffb84c",
            note: "The issuing signer revoked this authority; the signature is no longer trustworthy."
        },
        UNSIGNED: {
            banner: "uns", className: "unsigned", label: "UNSIGNED · Not Found in Ledger", color: "#8b93a8",
            note: "No signing authority is recorded for this digest. Treat as unofficial."
        },
    };

    const VB_ICONS = {
        auth: '<svg class="vbicon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><path d="m9 12 2 2 4-4"/></svg>',
        fake: '<svg class="vbicon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/></svg>',
        rev:  '<svg class="vbicon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg>',
        uns:  '<svg class="vbicon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></svg>',
    };

    // Big, obvious, one-tap action shown at the bottom of a verdict card so a
    // non-technical person always knows the single next step to take.
    function ctaForVerdict(verdict, likelyForged) {
        if (verdict === "PROVEN_FAKE") {
            return '<button class="cta cta-danger" onclick="reportFake()">Report this fake</button>' +
                   '<button class="cta cta-ghost" onclick="newVerify()">Verify another file</button>';
        }
        if (verdict === "AUTHENTIC") {
            return '<button class="cta cta-ok">Trust this file</button>' +
                   '<button class="cta cta-ghost" onclick="newVerify()">Verify another file</button>';
        }
        if (verdict === "REVOKED") {
            return '<button class="cta cta-warn" onclick="newVerify()">Check who signed it</button>' +
                   '<button class="cta cta-ghost" onclick="newVerify()">Verify another file</button>';
        }
        // UNSIGNED — lean toward "likely forged" when forensics flagged it.
        return '<button class="cta ' + (likelyForged ? "cta-warn" : "cta-ghost") + '" onclick="newVerify()">Verify another file</button>' +
               '<button class="cta cta-ghost" onclick="newVerify()">Check who signed it</button>';
    }

    window.reportFake = () => toast("Reported to the trust team. Thanks for keeping the record honest.", "success");
    window.newVerify = () => {
        const btn = $("verifyBtn");
        if (btn) btn.closest("form") && btn.closest("form").reset();
        const t = $("verifyStatus");
        if (t) t.textContent = "Drop a file above or paste a hash to check it.";
    };

    function renderVerificationRow(res, name, rawBlob) {
        // Layman-first headline (falls back to the legacy label/message for
        // older cached payloads so nothing ever renders blank).
        if (!res.ok) return toast(res.error, "error");
        const data = res.data;
        recordMetric(data.verdict);

        const p = VERDICT_PROFILES[data.verdict] || VERDICT_PROFILES.UNSIGNED;

        // Signer identity is rendered from a snapshot taken at signing time; the
        // email itself is never exposed on the public verify path.
        let signerMeta = '<span class="hash-view">No signature metadata.</span>';
        if (data.signer) {
            const orgs = [data.signer.institution, data.signer.designation].filter(Boolean).map(esc);
            signerMeta = `<strong>${esc(data.signer.name)}</strong>` +
                (orgs.length ? `<span class="role-tag">${orgs.join(" · ")}</span>` : "");
        }

        // Inline player wraps non-json/non-pdf inputs; the border colour inherits
        // the verdict so a forgery is visually unmistakable.
        let mediaPreview = "";
        if (rawBlob) {
            const ext = (name.split(".").pop() || "").toLowerCase();
            const isMedia = !name.toLowerCase().endsWith(".json") &&
                !["pdf", "txt"].includes(ext);
            if (isMedia) {
                const objUrl = URL.createObjectURL(rawBlob);
                const frame = ` style="border:2px solid ${p.color}"`;
                if (rawBlob.type.startsWith("video/") || ["mp4", "mov"].includes(ext)) {
                    mediaPreview = `<div class="media-frame"${frame}><video controls src="${objUrl}" style="width:100%; max-height:220px;"></video></div>`;
                } else if (rawBlob.type.startsWith("audio/") || ["mp3", "wav", "m4a", "ogg"].includes(ext)) {
                    mediaPreview = `<div class="media-frame"${frame}><audio controls src="${objUrl}" style="width:100%; display:block; background:#000;"></audio></div>`;
                }
            }
        }

        const web3Meta = data.tx_hash
            ? `<a href="${esc(data.blockchain_explorer)}" target="_blank" rel="noopener" style="color:var(--cyan); text-decoration:underline dashed rgba(6,213,250,0.5); text-underline-offset:3px;">${esc(data.tx_hash)}</a> <span class="chip cyan">L2 ANCHOR</span>`
            : '<span class="hash-view">Not anchored</span>';

        const headline = data.headline || p.label;

        // Forensic reasons panel: shown on EVERY verdict, right under the banner.
        // Uses plain language and inherits the verdict's colour so a forgery is
        // emotionally + visually unmistakable (red = danger, green = safe).
        const reasonsList = Array.isArray(data.reasons) ? data.reasons : [];
        let twinPanel = "";
        if (reasonsList.length) {
            const leanTag = (data.ai_suspected || data.edited_suspected || data.likely_forged)
                ? '<span class="forensic-flag">AI / EDITED</span>' : "";
            twinPanel = `
                <div class="forensic-panel">
                    <div class="forensic-head">WHY THIS FILE IS ${(data.likely_forged || data.verdict === "PROVEN_FAKE") ? "SUSPICIOUS" : "INSPECTED"} <span class="bullet">•</span> ${esc(data.forensic_leaning || "read")}${leanTag}</div>
                    ${reasonsList.map(r => `<div class="reason-card"><span class="reason-ic">!</span><span>${esc(r)}</span></div>`).join("")}
                </div>`;
        }

        // Plain one-line "what this means for you" + an obvious action button.
        const guidance = data.guidance || "";
        const ctaBlock = `
            <div class="verdict-actions">
                <div class="guidance-row"><span class="guidance-ic">?</span><span>${esc(guidance)}</span></div>
                <div class="cta-strip">${ctaForVerdict(data.verdict, data.likely_forged)}</div>
            </div>`;

        const row = document.createElement("div");
        row.className = `result ${p.className}`;
        row.innerHTML = `
            <div class="vbanner ${p.banner}">${VB_ICONS[p.banner]}<span style="flex:1">${headline}</span></div>
            ${twinPanel}
            <div class="verdict-note">${esc(data.message || p.note)}</div>
            <dl class="meta-grid">
                <dt>File</dt><dd><span class="hash-view">${esc(name)}</span></dd>
                <dt>SHA-256</dt><dd><span class="copy-hash" onclick="copyHash(this, '${esc(data.hash)}')">${shortHash(data.hash)} · copy</span></dd>
                <dt>Signer</dt><dd>${signerMeta}</dd>
                <dt>Web3 TX</dt><dd>${web3Meta}</dd>
            </dl>
            ${mediaPreview}
            ${ctaBlock}
        `;
        verifyResult.appendChild(row);
    }

    // ============================================================
    // AUTHORITY SIGNING (MEDIA & BROADCASTS)
    // ============================================================
    // Both handlers check the role badge state up front; un-approved signers
    // get a toast and nothing is transmitted.
    function requireSigningRole() {
        if (currentRoleApproved) return true;
        toast("Your signing role is pending administrator approval.", "warn");
        return false;
    }

    const signDrop = $("signDrop");
    const signInput = $("signInput");
    const signLabel = $("signLabel");
    wireDropzone(signDrop, signInput, signLabel);

    window.handleSignMedia = async () => {
        if (!requireSigningRole()) return;

        const files = signInput.files;
        if (!files.length) return toast("Attach files to sign.", "warn");

        const btn = $("signBtn");
        busy(btn, "Signing & Anchoring...");

        try {
            const fd = new FormData();
            for (const f of files) fd.append("files", f);

            const res = await safeFetch("/api/sign", { method: "POST", body: fd });
            if (res.ok) {
                downloadBlob(await res.response.blob(), files.length > 1 ? "signed_batch.zip" : `signed_${files[0].name}`);
                toast("Signed File Downloaded.", "success");
                fetchLedger();
            } else {
                toast(res.error || "Signing Failed", "error");
            }
        } finally {
            idle(btn);
        }
    };

    window.handleBroadcastNotice = async () => {
        if (!requireSigningRole()) return;

        const title = $("noticeTitle").value.trim();
        const msg = $("noticeMessage").value.trim();
        if (!title || !msg) return toast("Provide a title and message content.", "warn");

        const btn = $("broadcastBtn");
        busy(btn, "Signing & Issuing...");
        try {
        const fd = new FormData();
        fd.append("broadcast_title", title);
        fd.append("urgency_level", $("noticeUrgency").value);
        fd.append("message", msg);
        const mediaInput = $("noticeMedia");
        if (mediaInput && mediaInput.files && mediaInput.files[0]) {
            fd.append("media", mediaInput.files[0], mediaInput.files[0].name);
        }

            const res = await safeFetch("/api/sign_text", { method: "POST", body: fd });
            if (!res.ok) {
                toast(res.error || "Broadcast Failed", "error");
                return;
            }

            // The API returns the signed receipt as plain JSON — no attachment,
            // no body double-read, no blob() on a consumed stream. We build the
            // downloadable file here from the data we already hold.
            const receipt = res.data.receipt || null;
            const persisted = res.data.ledger_persisted === true;
            const fileName = `emergency_notice_${(title.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "notice")}.json`;
            downloadBlob(new Blob([JSON.stringify(receipt, null, 2)], { type: "application/json" }), fileName);

            toast(persisted
                ? `Notice signed & anchored: ${res.data.ipfs_cid || "simulated"} — added to ledger.`
                : "Notice signed — identical notice is already on the ledger.", "success");
            renderNoticeResult(receipt, persisted);
            $("noticeMessage").value = "";
            clearNoticeMedia(false);
            fetchLedger();
            loadBroadcasts();
        } finally {
            idle(btn);
        }
    };

    window.clearNoticeMedia = (alsoClear = true) => {
        const input = $("noticeMedia");
        const preview = $("noticeMediaPreview");
        if (input) input.value = "";
        if (preview) { preview.innerHTML = ""; preview.style.display = "none"; }
    };

    $("noticeMedia").addEventListener("change", () => {
        const preview = $("noticeMediaPreview");
        if (!preview) return;
        const input = $("noticeMedia");
        if (!input.files || !input.files[0]) { preview.style.display = "none"; preview.innerHTML = ""; return; }
        const f = input.files[0];
        const isImg = f.type.startsWith("image/");
        const url = URL.createObjectURL(f);
        preview.innerHTML = isImg
            ? `<img src="${url}" style="max-width:220px; max-height:140px; border-radius:10px; border:1px solid var(--card-border); display:block;">`
            : `<video src="${url}" controls muted style="max-width:240px; max-height:140px; border-radius:10px; border:1px solid var(--card-border); display:block;"></video>`;
        preview.style.display = "block";
    });

    // Renders a small on-page proof of the issuing result below the broadcast
    // form so a successful sign is visible even if the browser blocks downloads.
    function renderNoticeResult(receipt, persisted) {
        const box = $("noticeResult");
        if (!box || !receipt) return;
        const signer = receipt.signer || {};
        box.style.display = "block";
        box.innerHTML =
            `<b>${persisted ? "Notice issued & anchored to the ledger" : "Duplicate — already on the ledger"}</b> · ` +
            `hash <code>${esc(String(receipt.file_hash || "").slice(0, 16))}…</code>` +
            ` · ${esc(String(receipt.urgency || ""))} · ` +
            `<code>${esc(String(receipt.signature || "").slice(0, 20))}…</code><br/><small>` +
            esc(`${receipt.timestamp || ""} · ${signer.name || ""}${signer.designation ? " (" + signer.designation + ", " + (signer.institution || "?") + ")" : ""}`) +
            `</small>`;
    }

    // ============================================================
    // PUBLIC EMERGENCY NOTICE BOARD (breaking feed + view-all)
    // ============================================================
    let broadcasts = [];
    const URGENCY_META = { "CRITICAL": "#fb3a6b", "HIGH": "#ffb84c", "ADVISORY": "#f7cf4d" };

    function noticeMediaHtml(b, small) {
        if (!b.has_media) return "";
        const url = `/api/broadcasts/${b.file_hash}/media`;
        const isImg = (b.media_type || "").startsWith("image/");
        const style = small
            ? "max-width:100%; max-height:150px; width:auto; border-radius:10px; border:1px solid var(--card-border); display:block; margin:0 0 10px;"
            : "max-width:100%; max-height:340px; width:auto; border-radius:12px; border:1px solid var(--card-border); display:block; margin:8px 0 12px;";
        return isImg
            ? `<img src="${url}" alt="attached media" loading="lazy" style="${style}">`
            : `<video src="${url}" controls preload="metadata" style="${style}"></video>`;
    }

    function broadcastCard(b) {
        const urgency = (b.urgency || "HIGH").toUpperCase();
        const color = URGENCY_META[urgency] || "#fb3a6b";
        const t = String(b.timestamp || "").replace(" UTC", "");
        const canDel = b.can_delete === true && adminSessionActive;
        return `<article class="broadcast-card">
            <div class="broadcast-accent" style="background:${color};"></div>
            <div style="flex: 1; min-width: 0;">
                <div class="broadcast-head">
                    <span class="urgency-pill" style="color:${color}; border: 1px solid ${color}55; background: ${color}14;">${urgency}</span>
                    <span class="broadcast-title">${esc(b.title)}</span>
                    <span class="broadcast-time">${esc(t)} · UTC</span>
                </div>
                ${noticeMediaHtml(b, false)}
                ${b.content
                    ? `<p class="broadcast-body">${esc(b.content)}</p>`
                    : `<p class="broadcast-body" style="color: var(--text-md);">Message on file.</p>`}
                <div class="broadcast-meta">
                    <span>↳ signed by <b style="color: var(--emerald);">${esc(b.signer)}</b> · ${esc(b.institution)}${b.designation ? " · " + esc(b.designation) : ""}</span>
                    <button class="action-link" onclick="copyBroadcastHash(this, '${b.file_hash}')">⧉ copy hash</button>
                </div>
                <div class="broadcast-actions">
                    ${b.content || b.has_media ? `<button class="action-link" onclick="verifyBroadcast('${b.file_hash}')">Verify this notice</button>` : ""}
                    ${canDel ? `<button class="action-link danger" onclick="deleteBroadcast('${b.file_hash}')">Retract Notice</button>` : ""}
                </div>
            </div>
        </article>`;
    }

    async function loadBroadcasts() {
        const res = await safeFetch("/api/broadcasts?limit=200");
        if (!res.ok) return;
        broadcasts = res.data.broadcasts || [];
        renderNoticeFeed();
        renderBroadcastManager();
    }

    // Parses the "YYYY-MM-DD HH:MM:SS UTC" string as a UTC epoch (robust across
    // browsers, unlike new Date() on that loosely-specified format).
    function parseBroadcastDate(t) {
        const m = /^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/.exec(String(t || ""));
        if (!m) return 0;
        return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
    }

    // Compact card for the auto-scrolling rail (no full message body). Cards
    // with media grow to a taller uniform height and show a thumbnail on the
    // right, so the seamless ticker seam stays perfect (every card is the same
    // fixed height whether or not it carries media).
    function noticeFeedItem(b) {
        const urgency = (b.urgency || "HIGH").toUpperCase();
        const color = URGENCY_META[urgency] || "#fb3a6b";
        const t = String(b.timestamp || "").replace(" UTC", "");
        const mediaHtml = b.has_media
            ? `<div class="ni-thumb">${(b.media_type || "").startsWith("image/")
                ? `<img src="/api/broadcasts/${b.file_hash}/media" alt="attached" loading="lazy">`
                : `<video src="/api/broadcasts/${b.file_hash}/media" muted preload="metadata" onmouseover="this.play()" onmouseout="this.pause()"></video>`}</div>`
            : "";
        return `<div class="notice-item${b.has_media ? " with-media" : ""}">
            <span class="urgency-dot" style="background:${color};"></span>
            <div style="min-width: 0; flex: 1;">
                <div class="ni-title">${esc(b.title)}</div>
                <div class="ni-meta">
                    <span class="ni-when">${esc(t)} · UTC</span>
                    <span class="ni-who">signed by <b>${esc(b.signer)}</b></span>
                </div>
                <div class="ni-actions">
                    ${b.content || b.has_media ? `<button class="action-link" onclick="verifyBroadcast('${b.file_hash}')">Verify</button>` : ""}
                    <button class="action-link" onclick="copyBroadcastHash(this, '${b.file_hash}')">Copy hash</button>
                </div>
            </div>
            ${mediaHtml}
        </div>`;
    }

    // The right rail is a fixed-height window showing AT MOST 3 cards at once.
    // Logging shows exactly 3 live notices in the last 24h; with more than 3,
    // the list is duplicated and translated upward for a seamless ticker. With
    // 3 or fewer the rail simply sits static — nothing to scroll, no duplicated
    // "two copies of everything" look.
    function renderNoticeFeed() {
        const feed = $("noticeFeed");
        const empty = $("noticeEmpty");
        const count = $("noticeFeedCount");
        if (!feed) return;
        const cutoff = Date.now() - 86400000;
        const active = broadcasts.filter((b) => parseBroadcastDate(b.timestamp) >= cutoff);
        const show = active.length > 0;
        const scroll = active.length > 3;
        if (show) {
            const cards = active.map(noticeFeedItem).join("");
            feed.innerHTML = scroll ? cards + cards : cards;
        } else {
            feed.innerHTML = "";
        }
        if (scroll) {
            feed.style.animationName = "notice-scroll";
            feed.style.animationDuration = Math.max(20, active.length * 6) + "s";
            feed.style.animationTimingFunction = "linear";
            feed.style.animationIterationCount = "infinite";
        } else {
            feed.style.animation = "none";
        }
        if (empty) empty.style.display = show ? "none" : "flex";
        if (count) count.textContent = show ? `${active.length} active · ${broadcasts.length} total` : `${broadcasts.length} total`;
    }

    // Admin area: list every broadcast this viewer may retract (their own for a
    // normal admin, every broadcast for a super admin). Permission is enforced
    // server-side per row; the client merely surfaces what the API allowed.
    function renderBroadcastManager() {
        const box = $("broadcastManage");
        const section = $("broadcastManageSection");
        if (!box || !section) return;
        const deletable = broadcasts.filter((b) => b.can_delete === true);
        if (!adminSessionActive || !deletable.length) { section.style.display = "none"; return; }
        section.style.display = "block";
        const scope = $("manageScopeLabel");
        if (scope) scope.textContent = isSuperAdmin ? "All Issued Broadcasts" : "My Issued Broadcasts";
        box.innerHTML = deletable.map((b) => {
            const color = URGENCY_META[(b.urgency || "HIGH").toUpperCase()] || "#fb3a6b";
            const t = String(b.timestamp || "").replace(" UTC", "");
            return `<div class="broadcast-card" style="padding: 10px 14px;">
                <div class="broadcast-accent" style="background:${color};"></div>
                <div style="flex: 1; min-width: 0;">
                    <div class="broadcast-head">
                        <span class="broadcast-title" style="font-size: 13px;">${esc(b.title)}</span>
                        <span class="broadcast-time">${esc(t)} · UTC</span>
                    </div>
                    <div class="broadcast-actions" style="margin-top: 6px;">
                        <button class="action-link danger" onclick="deleteBroadcast('${b.file_hash}')">🗑 Retract Notice</button>
                    </div>
                </div>
            </div>`;
        }).join("");
    }

    window.viewAllBroadcasts = () => {
        const modal = $("viewAllModal");
        modal.classList.remove("hidden");
        setTimeout(() => {
            modal.style.opacity = "1";
            $("viewAllModalContent").style.transform = "translateY(0)";
        }, 10);
        const wrap = $("allBroadcasts");
        $("allEmpty").style.display = broadcasts.length ? "none" : "block";
        wrap.innerHTML = broadcasts.map(broadcastCard).join("");
    };

    window.closeViewAll = () => {
        const modal = $("viewAllModal");
        modal.style.opacity = "0";
        setTimeout(() => modal.classList.add("hidden"), 250);
    };

    $("viewAllModal").addEventListener("click", (e) => {
        if (e.target.id === "viewAllModal") window.closeViewAll();
    });

    window.copyBroadcastHash = (el, value) => window.copyHash(el, value);

    // Loads the exact signed text into the public Verifier so anyone can prove
    // the on-screen notice is authentic — closing the README's loop. Notices
    // carrying media can't be replayed as plain text (their hash binds the
    // bytes too), so for those we surface the ledger hash instead.
    window.verifyBroadcast = (hash) => {
        const b = broadcasts.find((x) => x.file_hash === hash);
        if (!b) return;
        if (b.content && !b.has_media) {
            $("verifyTextInput").value = b.content;
            switchVerifyMode("text");
            setTimeout(() => $("verifyBtn").scrollIntoView({ behavior: "smooth", block: "center" }), 80);
            toast("Exact signed text loaded into the Verifier.", "info");
        } else {
            window.copyHash(null, b.file_hash);
            toast(b.has_media ? "Notice includes signed media — copied its ledger hash." : "Legacy notice — message on file. Copied its ledger hash.", "info");
        }
    };

    window.deleteBroadcast = async (file_hash) => {
        const b = broadcasts.find((x) => x.file_hash === file_hash);
        if (!confirm(`Retract ${b ? "“" + b.title + "”" : "this notice"}? It vanishes from the public board and is marked retracted in the ledger.`)) return;
        const fd = new FormData();
        fd.append("file_hash", file_hash);
        const res = await safeFetch("/api/broadcasts/delete", { method: "POST", body: fd });
        if (!res.ok) { toast(res.error || "Retraction failed.", "error"); return; }
        toast("Notice retracted — removed from the public board.", "success");
        fetchLedger();
        loadBroadcasts();
    };

    // ============================================================
    // LEDGER TABLE + FILTERS
    // ============================================================
    const TX_EXPLORER = "https://amoy.polygonscan.com/tx/";

    window.applyFilters = () => {
        const inst = $("filterInst").value;
        const filtered = globalBlocks.filter((b) => {
            const bInst = b.signer_institution || "Independent";
            return inst === "ALL" || bInst === inst;
        });

        $("ledgerCount").innerText = `${filtered.length} Records`;
        const tbody = $("ledgerBody");
        if (!filtered.length) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">No records found.</td></tr>';
            return;
        }

        tbody.innerHTML = filtered.map((b) => `
            <tr>
                <td>${b.timestamp.replace(" UTC", "")}</td>
                <td style="color:var(--text-hi); font-weight:600;">${esc(b.signer_name)}</td>
                <td>${esc(b.signer_institution || "Independent")}<br/><span style="opacity:0.6;font-size:10px;">${esc(b.signer_designation || "Signer")}</span></td>
                <td>${esc(b.filename)}</td>
                <td>${b.tx_hash ? `<a href="${TX_EXPLORER}${b.tx_hash}" target="_blank" style="color:var(--cyan);">TX Hash</a>` : "Pending"}</td>
                <td>${b.is_revoked
                    ? '<span class="status-pill revoked">REVOKED</span>'
                    : '<span class="status-pill active">ANCHORED</span>'}</td>
            </tr>`).join("");
    };

    async function fetchLedger() {
        const res = await safeFetch("/api/ledger");
        if (!res.ok) return;

        globalBlocks = res.data.blocks || [];
        globalSigners = res.data.signers || {};
        isSuperAdmin = res.data.is_super_admin;

        // Super-admin-only panels: role assignment blanket + admin command bar.
        $("adminControlsSection").style.display = isSuperAdmin ? "block" : "none";
        const roleAssignSection = $("roleAssignSection");
        if (roleAssignSection) roleAssignSection.style.display = isSuperAdmin ? "block" : "none";

        buildRoleTargetOptions();
        buildRollbackOptions();
        buildInstitutionFilter();
        renderIdentities();

        applyFilters();
        // If the graph is on screen, signer lists (network) just changed — refresh.
        if (showingGraph) setTimeout(loadNetworkGraph, 50); // let the DOM reflow first
    }

    // Dropdown of every known signer for the super-admin role assignment panel.
    function buildRoleTargetOptions() {
        const target = $("roleTarget");
        if (!target) return;
        target.innerHTML = '<option value="">Select signer (by email)...</option>' +
            Object.values(globalSigners)
                .map((s) => `<option value="${esc(s.email)}">${esc(s.name)} — ${esc(s.email)}${s.is_revoked ? " (revoked)" : ""}</option>`)
                .join("");
    }

    // Rollback restore points: the 15 most recent signing timestamps.
    function buildRollbackOptions() {
        const select = $("rollbackSelect");
        if (!select) return;
        const restorePoints = [...new Set(globalBlocks.map((b) => b.timestamp))]
            .sort().reverse().slice(0, 15);
        select.innerHTML = '<option value="">Restore Point...</option>' +
            restorePoints.map((ts) => `<option value="${esc(ts)}">${ts.replace(" UTC", "")}</option>`).join("");
    }

    // Institution dropdown for the ledger table filter.
    function buildInstitutionFilter() {
        const filterInst = $("filterInst");
        if (!filterInst) return;
        const institutions = [...new Set(globalBlocks.map((b) => b.signer_institution).filter(Boolean))];
        filterInst.innerHTML = '<option value="ALL">All Institutions</option>' +
            institutions.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join("");
    }

    // The "key issuance ledger": every authority identity, active or revoked,
    // with per-user revoke/unrevoke controls. Super admins additionally see the
    // exact key issue date (a requirement of the problem statement).
    function initials(name) {
        return (name || "").split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0]).join("").toUpperCase();
    }

    function renderIdentities() {
        const activeHTML = [];
        const revokedHTML = [];

        Object.values(globalSigners).forEach((s) => {
            const canRevoke = (isSuperAdmin || s.email === currentUserEmail) && !s.is_revoked;
            const issueDate = (isSuperAdmin && s.registered_at)
                ? `<div style="font-size:10px; color:var(--text-lo); margin-top:6px; font-family:'JetBrains Mono', monospace;">🔑 Issued: ${s.registered_at.replace(" UTC", "")}</div>` : "";
            const revokeBtn = canRevoke
                ? `<button class="btn btn-danger btn-sm" onclick="handleRevokeClick('${esc(s.email)}')">Revoke Key</button>` : "";
            const reinstateBtn = s.is_revoked
                ? (isSuperAdmin
                    ? `<button class="btn btn-primary btn-sm" onclick="handleReinstateClick('${esc(s.email)}')">Unrevoke</button>`
                    : (s.email === currentUserEmail
                        ? `<button class="btn btn-primary btn-sm" onclick="handleUserUnrevokeClick()">Unrevoke</button>` : ""))
                : "";

            const card = `
                <div class="authority-item" style="${s.is_revoked ? "border-color: rgba(251,58,107,0.2); background: rgba(251,58,107,0.02);" : ""}">
                    <div class="authority-avatar" style="${s.is_revoked ? "background: var(--grad-danger); box-shadow: none;" : ""}">${initials(s.name)}</div>
                    <div class="authority-info">
                        <div class="authority-name" style="${s.is_revoked ? "color: var(--text-md); text-decoration: line-through;" : ""}">${esc(s.name)} ${s.email === currentUserEmail ? "(You)" : ""}</div>
                        <div class="authority-id">${esc(s.designation || "Signer")}${s.institution ? ` · ${esc(s.institution)}` : ""} · ${esc(s.email)}</div>
                        ${issueDate}
                    </div>
                    <div style="display:flex; gap: 8px; align-items: center;">
                        <span class="status-pill ${s.is_revoked ? "revoked" : "active"}">${s.is_revoked ? "revoked" : "active"}</span>
                        ${revokeBtn}
                        ${reinstateBtn}
                    </div>
                </div>`;

            if (s.is_revoked) revokedHTML.push(card);
            else activeHTML.push(card);
        });

        $("activeInstList").innerHTML = activeHTML.length
            ? activeHTML.join("")
            : '<div class="text-md font-mono" style="font-size:11px;">No active signers found.</div>';
        $("revokedInstList").innerHTML = revokedHTML.length
            ? revokedHTML.join("")
            : '<div class="text-md font-mono" style="font-size:11px;">No revoked signers.</div>';

        const authCount = $("authCount");
        if (authCount) authCount.textContent = Object.values(globalSigners).length;
    }

    // ============================================================
    // SUPER-ADMIN ROLE ASSIGNMENT (ANTI-IMPERSONATION)
    // ============================================================
    $("assignRoleBtn").addEventListener("click", () => handleAssignRole());

    window.handleAssignRole = async () => {
        if (!isSuperAdmin) return toast("Super Admin Clearance Required.", "error");

        const email = $("roleTarget").value;
        const desig = $("roleDesignation").value.trim();
        const inst = $("roleInstitution").value.trim();
        if (!email || !desig || !inst) return toast("Select a signer and fill the post & institution.", "warn");

        const fd = new FormData();
        fd.append("target_email", email);
        fd.append("designation", desig);
        fd.append("institution", inst);

        const res = await safeFetch("/api/admin/assign_role", { method: "POST", body: fd });
        if (res.ok) {
            toast(`Role assigned: ${desig} · ${inst}`, "success");
            $("roleDesignation").value = "";
            $("roleInstitution").value = "";
            fetchLedger();
        } else {
            toast(res.error, "error");
        }
    };

    // ============================================================
    // REVOKE / REINSTATE KILL-SWITCH MODAL
    // ============================================================
    const setupPinInput = $("setupPinInput");
    const verifyPinInput = $("verifyPinInput");
    const confirmRevokeBtn = $("confirmRevokeBtn");
    const doubleWarningSection = $("doubleWarningSection");
    const setupPinSection = $("setupPinSection");
    const verifyPinSection = $("verifyPinSection");

    // PIN fields are digits-only; the confirm button only arms on 5 digits.
    const checkPinInput = (e) => {
        const val = e.target.value.trim().replace(/[^0-9]/g, "");
        e.target.value = val;
        confirmRevokeBtn.disabled = val.length !== 5;
    };
    if (setupPinInput) setupPinInput.addEventListener("input", checkPinInput);
    if (verifyPinInput) verifyPinInput.addEventListener("input", checkPinInput);

    // Show a modal, dimming the backdrop as it fades in.
    function openModal(focusSetup, focusVerify, alreadyHasPin) {
        const modal = $("revokeModal");
        modal.classList.remove("hidden");
        setTimeout(() => {
            modal.style.opacity = "1";
            $("revokeModalContent").style.transform = "translateY(0)";
        }, 10);

        // If the signer has no PIN yet, jump focus to the PIN-creation field;
        // otherwise prepopulate focus for the "verify existing PIN" field.
        if (focusSetup && !alreadyHasPin && !isSuperAdmin) setTimeout(() => $(focusSetup).focus(), 300);
        else if (focusVerify) setTimeout(() => $(focusVerify).focus(), 300);
    }

    // Which ever PIN screen is currently visible holds the typed value.
    const readPin = () => (isSettingPin ? setupPinInput : verifyPinInput).value;

    // Normal signers see a scary FINAL WARNING before the request actually fires.
    function showDoubleWarning() {
        isDoubleWarningPhase = true;
        setupPinSection.classList.add("hidden");
        verifyPinSection.classList.add("hidden");
        doubleWarningSection.classList.remove("hidden");
        confirmRevokeBtn.textContent = "Yes, Permanently Revoke";
        confirmRevokeBtn.className = "btn btn-danger";
        confirmRevokeBtn.disabled = false;
    }

    window.handleRevokeClick = (email) => {
        currentRevokeTarget = email;
        isReinstating = false;
        isDoubleWarningPhase = false;
        doubleWarningSection.classList.add("hidden");
        $("revokeModalContent").style.borderColor = "rgba(251,58,107,0.4)";

        const hasPin = globalSigners[email] ? globalSigners[email].has_pin : false;
        const title = $("revokeModalTitle");
        const desc = $("revokeModalDesc");

        if (isSuperAdmin) {
            // Top-level override: no PIN dance, straight to the force-revoke.
            isSettingPin = false;
            setupPinSection.classList.add("hidden");
            verifyPinSection.classList.add("hidden");
            title.textContent = "Super Admin Override";
            title.style.color = "var(--rose)";
            desc.innerHTML = `You are about to force-revoke <strong style="color:var(--text-hi)">${esc(email)}</strong>.`;
            confirmRevokeBtn.disabled = false;
            confirmRevokeBtn.textContent = "Force Revoke";
            confirmRevokeBtn.className = "btn btn-danger";
        } else if (!hasPin) {
            // First revocation for this signer — build the kill-switch PIN first.
            isSettingPin = true;
            setupPinSection.classList.remove("hidden");
            verifyPinSection.classList.add("hidden");
            title.textContent = "Security Setup Required";
            title.style.color = "var(--amber)";
            desc.innerHTML = `Create a <strong>5-digit PIN</strong> for <strong style="color:var(--text-hi)">${esc(email)}</strong>.`;
            setupPinInput.value = "";
            confirmRevokeBtn.disabled = true;
            confirmRevokeBtn.textContent = "Save PIN & Proceed";
            confirmRevokeBtn.className = "btn btn-danger";
        } else {
            // Normal signer with an existing PIN: confirm before pulling the trigger.
            isSettingPin = false;
            setupPinSection.classList.add("hidden");
            verifyPinSection.classList.remove("hidden");
            $("verifyPinLabel").textContent = "Enter your 5-digit Secret PIN";
            title.textContent = "Confirm Revocation";
            title.style.color = "var(--rose)";
            desc.innerHTML = `You are about to revoke <strong style="color:var(--text-hi)">${esc(email)}</strong>.`;
            verifyPinInput.value = "";
            confirmRevokeBtn.disabled = true;
            confirmRevokeBtn.textContent = "Verify & Proceed";
            confirmRevokeBtn.className = "btn btn-danger";
        }

        openModal("setupPinInput", "verifyPinInput", hasPin);
    };

    // Super admins restore a signer's identity after showing the victim's PIN
    // (or 00000 for legacy users that were created before PINs existed).
    window.handleReinstateClick = (email) => {
        currentRevokeTarget = email;
        isReinstating = true;
        isSettingPin = false;
        isDoubleWarningPhase = false;
        doubleWarningSection.classList.add("hidden");
        setupPinSection.classList.add("hidden");
        verifyPinSection.classList.remove("hidden");
        $("revokeModalContent").style.borderColor = "rgba(34,227,164,0.4)";

        const hasPin = globalSigners[email] ? globalSigners[email].has_pin : false;
        $("verifyPinLabel").innerHTML = hasPin
            ? "Enter user's exact 5-digit PIN"
            : "No PIN found (Legacy User). Enter <strong>00000</strong> to force bypass.";

        $("revokeModalTitle").textContent = "Super Admin: Reinstate Key";
        $("revokeModalTitle").style.color = "var(--emerald)";
        $("revokeModalDesc").innerHTML = `Please verify with <strong style="color:var(--text-hi)">${esc(email)}</strong> out-of-band and enter their 5-digit PIN here to unrevoke their identity.`;
        verifyPinInput.value = "";

        confirmRevokeBtn.disabled = true;
        confirmRevokeBtn.textContent = "Reinstate Identity";
        confirmRevokeBtn.className = "btn btn-primary";
        openModal(null, "verifyPinInput", true);
    };

    // Non-super-admins can't un-revoke themselves in the UI; show the info popup
    // explaining the 24h super-admin support channel instead.
    window.handleUserUnrevokeClick = () => {
        const modal = $("userUnrevokeModal");
        modal.classList.remove("hidden");
        setTimeout(() => {
            modal.style.opacity = "1";
            $("userUnrevokeModalContent").style.transform = "translateY(0)";
        }, 10);
    };

    window.closeUserUnrevokeModal = () => {
        const modal = $("userUnrevokeModal");
        modal.style.opacity = "0";
        $("userUnrevokeModalContent").style.transform = "translateY(20px)";
        setTimeout(() => modal.classList.add("hidden"), 300);
    };

    window.closeRevokeModal = () => {
        const modal = $("revokeModal");
        modal.style.opacity = "0";
        $("revokeModalContent").style.transform = "translateY(20px)";
        setTimeout(() => {
            modal.classList.add("hidden");
            currentRevokeTarget = null;
        }, 300);
    };

    const cancelRevokeBtn = $("cancelRevokeBtn");
    if (cancelRevokeBtn) cancelRevokeBtn.addEventListener("click", closeRevokeModal);

    confirmRevokeBtn.addEventListener("click", async () => {
        if (!currentRevokeTarget) return;

        // Un-revoke flow: needs only the victim's PIN, straight to the API.
        if (isReinstating) {
            executeApiCall("/api/reinstate", verifyPinInput.value);
            return;
        }

        if (isSuperAdmin) {
            executeApiCall("/api/revoke", null);
            return;
        }

        // Non-super-admin: first click on a fresh PIN arms the "final warning"
        // phase; a second click on the warning actually performs the revoke. The
        // new PIN is registered the moment it is typed, so a refresh can't lose it.
        if (!isDoubleWarningPhase) {
            const pin = readPin();
            if (!pin || pin.length !== 5) return toast("A 5-digit PIN is required.", "error");

            if (isSettingPin) {
                const fdPin = new FormData();
                fdPin.append("pin", pin);
                safeFetch("/api/set_pin", { method: "POST", body: fdPin });
                if (globalSigners[currentRevokeTarget]) globalSigners[currentRevokeTarget].has_pin = true;
            }
            showDoubleWarning();
            return;
        }

        executeApiCall("/api/revoke", readPin());
    });

    // The single function that actually talks to /api/revoke & /api/reinstate.
    async function executeApiCall(endpoint, pin) {
        const originalText = confirmRevokeBtn.textContent;
        confirmRevokeBtn.disabled = true;
        confirmRevokeBtn.innerHTML = `${SPINNER}Processing...`;

        const fd = new FormData();
        fd.append("target_email", currentRevokeTarget);
        if (pin) fd.append("pin", pin);

        const res = await safeFetch(endpoint, { method: "POST", body: fd });

        if (res.ok) {
            closeRevokeModal();
            toast(endpoint === "/api/revoke" ? "Identity Revoked." : "Identity Reinstated.",
                  endpoint === "/api/revoke" ? "error" : "success");
            fetchLedger();
        } else {
            toast(res.error, "error");
            // A wrong PIN rolls the modal back to the PIN-entry screen.
            if (res.error.toLowerCase().includes("incorrect")) {
                isDoubleWarningPhase = false;
                doubleWarningSection.classList.add("hidden");
                (isSettingPin ? setupPinSection : verifyPinSection).classList.remove("hidden");
            }
        }

        confirmRevokeBtn.disabled = false;
        confirmRevokeBtn.textContent = res.ok ? originalText
            : (res.error.toLowerCase().includes("incorrect") ? "Verify & Proceed"
               : (isDoubleWarningPhase ? "Yes, Permanently Revoke" : originalText));
    }

    // ============================================================
    // SYSTEM / SUPER-ADMIN COMMANDS & WEB3 SYNC
    // ============================================================
    window.executeDDay = async () => {
        toast("D-DAY INITIATED.", "warn");
        const res = await safeFetch("/api/dday", { method: "POST" });
        if (res.ok) { if (adminSessionActive) fetchLedger(); }
        else toast(res.error, "error");
    };

    window.executeRollback = async () => {
        const targetTS = $("rollbackSelect").value;
        if (!targetTS) return toast("Select a point.", "warn");
        const fd = new FormData();
        fd.append("target_timestamp", targetTS);
        const res = await safeFetch("/api/rollback", { method: "POST", body: fd });
        if (res.ok) {
            toast(`Restore Complete to ${targetTS.replace(" UTC", "")}`, "success");
            if (adminSessionActive) fetchLedger();
        } else toast(res.error, "error");
    };

    window.syncToBlockchain = async () => {
        const btn = $("syncChainBtn");
        busy(btn, "Computing Merkle Root...");
        const res = await safeFetch("/api/blockchain/sync", { method: "POST" });
        if (res.ok) {
            if (res.data.status === "UP_TO_DATE") toast("Blockchain is already in sync.", "info");
            else toast(`Layer-2 Sync Complete! TX: ${res.data.tx_hash.slice(0, 16)}...`, "success");
            fetchLedger();
        } else {
            toast(res.error || "Sync Failed.", "error");
        }
        idle(btn);
    };

    // ============================================================
    // VIS.JS DEPENDENCY MAP
    // ============================================================
    window.toggleLedgerView = () => {
        showingGraph = !showingGraph;
        $("viewToggleBtn").innerText = showingGraph ? "Show Table View" : "Show Dependency Map";
        $("ledgerTableContainer").classList.toggle("hidden", showingGraph);
        $("ledgerGraphContainer").classList.toggle("hidden", !showingGraph);
        // Delay lets the freshly-visible container size up before Vis.js measures it.
        if (showingGraph) setTimeout(loadNetworkGraph, 50);
    };

    async function loadNetworkGraph() {
        const res = await safeFetch("/api/network");
        if (!res.ok) return;

        const nodes = new vis.DataSet((res.data.nodes || []).map((n) => {
            if (n.group === "authority") {
                return { id: n.id, label: n.label, shape: "dot", size: 25,
                         color: { background: n.is_revoked ? "#fb3a6b" : "#22e3a4", border: "#27272a" },
                         font: { color: "#e4e4e7", size: 14 } };
            }
            // Compromised (standard-mode) files get an explicit "(EXPOSED)" flag.
            const label = (n.label || "") + (n.is_compromised ? "\n(EXPOSED)" : "");
            return { id: n.id, label, shape: "box",
                     color: { background: n.is_revoked ? "#fb3a6b" : "#6366f1", border: "#27272a" },
                     font: { color: "#e4e4e7", size: 12 } };
        }));

        const edges = new vis.DataSet(res.data.edges || []);
        if (networkObj) networkObj.destroy();
        networkObj = new vis.Network(
            $("ledgerGraphContainer"),
            { nodes, edges },
            { layout: { hierarchical: { enabled: true, direction: "LR", levelSeparation: 300 } },
              physics: false,
              edges: { color: "rgba(255,255,255,0.2)", width: 2, smooth: { type: "cubicBezier" } } }
        );
    }

    // ============================================================
    // ANALYTICS & CHART.JS
    // ============================================================
    // One row per verdict drives both the KPI tiles and the chart, so the verdict
    // vocabulary lives in exactly one place (no scattered label/colour strings).
    const VERDICT_META = [
        { key: "AUTHENTIC",   el: "stat-auth", label: "Authentic",  color: "#22e3a4" },
        { key: "PROVEN_FAKE", el: "stat-fake", label: "Forgeries",  color: "#fb3a6b" },
        { key: "REVOKED",     el: "stat-rev",  label: "Revoked",    color: "#ffb84c" },
        { key: "UNSIGNED",    el: "stat-uns",  label: "Unsigned",   color: "#8b93a8" },
    ];

    window.switchAnalyticsScope = (scope) => {
        // Global scope only exists for super admins; reset the dropdown otherwise.
        if (scope === "global" && !isSuperAdmin) {
            toast("Super Admin Clearance Required.", "error");
            $("analyticsScope").value = currentAnalyticsScope;
            return;
        }
        currentAnalyticsScope = scope;
        loadAnalytics();
    };

    async function loadAnalytics() {
        // Merge whichever source is in scope into a full four-key stats object.
        let source;
        if (currentAnalyticsScope === "global") {
            const res = await safeFetch("/api/analytics");
            source = res.ok ? res.data.stats : null;
        } else {
            source = currentAnalyticsScope === "session" ? memorySessionMetrics : readLocalMetrics();
        }
        const stats = { ...EMPTY_METRICS, ...(source || {}) };

        VERDICT_META.forEach(({ key, el }) => {
            const tile = $(el);
            if (tile) tile.textContent = stats[key];
        });

        renderThreatChart(stats);
    }

    function renderThreatChart(stats) {
        const canvas = $("threatChart");
        if (!canvas) return;
        if (threatChartObj) threatChartObj.destroy();
        threatChartObj = new Chart(canvas.getContext("2d"), {
            type: "bar",
            data: {
                labels: VERDICT_META.map((v) => v.label),
                datasets: [{
                    label: "Events",
                    data: VERDICT_META.map((v) => stats[v.key]),
                    backgroundColor: VERDICT_META.map((v) => v.color),
                    borderRadius: 4
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#a5adc0" } },
                    x: { grid: { display: false }, ticks: { color: "#a5adc0", font: { family: "JetBrains Mono" } } },
                },
            },
        });
    }

    // ============================================================
    // INITIALIZATION
    // ============================================================
    // Hover spotlight trail follows the cursor across glass panels.
    document.querySelectorAll(".glass-panel").forEach((panel) => {
        panel.addEventListener("mousemove", (e) => {
            const rect = panel.getBoundingClientRect();
            panel.style.setProperty("--mx", `${((e.clientX - rect.left) / rect.width) * 100}%`);
            panel.style.setProperty("--my", `${((e.clientY - rect.top) / rect.height) * 100}%`);
        });
    });

    // The only dynamically-injected keyframe (used by the busy-button spinner).
    const kf = document.createElement("style");
    kf.textContent = "@keyframes spin{to{transform:rotate(360deg)}}";
    document.head.appendChild(kf);

    checkAuthStatus();
    fetchPublicStats();
    setTimeout(() => toast("Provenance engine online", "success"), 400);
})();