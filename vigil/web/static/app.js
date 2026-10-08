// Everything coming back from a scan (titles, evidence) can contain text from the
// scanned site, which is attacker-controlled. So we build the DOM with textContent
// only and never innerHTML with data, or the scanner itself would be an XSS vector.
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) k === "class" ? (n.className = v) : n.setAttribute(k, v);
  for (const k of kids) if (k != null) n.append(k);
  return n;
}
function withCode(text) {           // render `code` spans safely
  const frag = document.createDocumentFragment();
  text.split(/`([^`]+)`/).forEach((p, i) => frag.append(i % 2 ? el("code", {}, p) : p));
  return frag;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- Scan and report options (remembered in this browser) -------------------
const OPTS_KEY = "vigil.options";
const checked = (name) => $$(`input[name=${name}]:checked`).map((i) => i.value);
function readOpts() {
  return { checks: checked("check"), sections: checked("section"), min: $("#min").value, evidence: $("#evidence").checked };
}
function restoreOpts() {
  let o;
  try { o = JSON.parse(localStorage.getItem(OPTS_KEY)); } catch { return; }
  if (!o) return;
  for (const name of ["check", "section"]) {
    const on = new Set(o[name === "check" ? "checks" : "sections"] || []);
    for (const i of $$(`input[name=${name}]`)) i.checked = on.has(i.value);
  }
  if (o.min) $("#min").value = o.min;
  $("#evidence").checked = o.evidence !== false;
}
// Query string for report links; empty when the reader wants the full default report.
function reportQuery() {
  const o = readOpts(), all = $$("input[name=section]").length;
  if (o.sections.length === all && o.min === "info" && o.evidence) return "";
  return "?" + new URLSearchParams({ sections: o.sections.join(","), min: o.min, evidence: o.evidence ? 1 : 0 });
}
// Report links carry data-id/data-ext and get their href here, so changing an option updates them all.
function reportLink(id, ext, attrs, label) {
  return el("a", { ...attrs, "data-id": id, "data-ext": ext }, label);
}
function refreshLinks() {
  const q = reportQuery();
  for (const a of $$("a[data-id]")) a.href = `/scans/${encodeURIComponent(a.dataset.id)}/report${a.dataset.ext}${q}`;
}
$("#opts").addEventListener("change", () => {
  try { localStorage.setItem(OPTS_KEY, JSON.stringify(readOpts())); } catch { /* storage unavailable */ }
  refreshLinks();
});

// --- Preview: the PDF inline in a dialog, with the same downloads alongside ---
const dialog = $("#preview");
function openPreview(id) {
  for (const a of ["#pv-pdf", "#pv-docx"]) $(a).dataset.id = id;
  refreshLinks();
  const url = $("#pv-pdf").href + ($("#pv-pdf").href.includes("?") ? "&" : "?") + "preview=1";
  $("#pv-frame").src = url;
  $("#pv-open").href = url;
  dialog.showModal();
}
$("#result").addEventListener("click", (ev) => {
  const btn = ev.target.closest("[data-preview]");
  if (btn) openPreview(btn.dataset.preview);
});
$("#pv-close").addEventListener("click", () => dialog.close());
dialog.addEventListener("click", (ev) => { if (ev.target === dialog) dialog.close(); });  // backdrop click
dialog.addEventListener("close", () => { $("#pv-frame").src = "about:blank"; });

// --- Results --------------------------------------------------------------
function details(r) {
  const body = el("div", { class: "scan-body" });
  body.append(el("div", { class: "report-panel" },
    el("div", { class: "report-copy" },
      el("strong", {}, "Get the full report"),
      el("span", { class: "muted" }, "A ready-to-share document, formatted with your report options above.")),
    el("div", { class: "report-actions" },
      el("button", { class: "btn btn-primary", type: "button", "data-preview": r.id }, "Preview report"),
      reportLink(r.id, ".pdf", { class: "btn btn-secondary", download: "" }, "⬇ Download PDF"),
      reportLink(r.id, ".docx", { class: "btn btn-secondary", download: "" }, "⬇ Download Word"),
      reportLink(r.id, "", { class: "btn btn-ghost", target: "_blank", rel: "noopener" }, "View online ↗"))));
  for (const f of r.findings) {
    body.append(el("div", { class: `card s-${f.severity}` },
      el("div", { class: `sev t-${f.severity}` }, `${f.severity} · ${f.check}`),
      el("h3", {}, f.title),
      el("div", {}, f.description),
      f.recommendation ? el("div", { class: "fix" }, el("strong", {}, "Fix: "), withCode(f.recommendation)) : null,
      f.evidence ? el("span", { class: "ev" }, f.evidence) : null));
  }
  if (!r.findings.length) body.append(el("p", {}, "No issues found."));
  if (r.passed.length) body.append(el("p", { class: "muted" }, "Passed: " + r.passed.join(", ")));
  for (const e of r.errors) body.append(el("p", { class: "muted" }, "Note: " + e));
  return body;
}

// One <details> row per URL; repainting swaps its children so the row (and its open state) stays put.
function paint(job, state, text, data) {
  const badge = data ? el("div", { class: `grade g-${data.grade}` }, data.grade)
    : el("div", { class: `grade ${state}` }, state === "error" ? "!" : "");
  let meta = text;
  if (data) {
    const counts = Object.entries(data.summary).filter(([, n]) => n).map(([s, n]) => `${n} ${s}`).join(" · ");
    meta = `Score ${data.score}/100 · ${data.duration_ms} ms · ${counts || "no issues"}`;
  }
  job.node.className = `scan is-${state}`;
  job.node.replaceChildren(
    el("summary", {}, badge,
      el("div", { class: "scan-id" }, el("div", { class: "url" }, data ? data.final_url : job.url),
        el("div", { class: state === "error" ? "err" : "muted" }, meta))),
    data ? details(data) : null);
  if (data) refreshLinks();
}

async function runJob(job, checks) {
  paint(job, "pending", "Scanning…");
  for (let attempt = 0; attempt < 10; attempt++) {
    let res, data;
    try {
      res = await fetch("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: job.url, authorized: true, checks }) });
      data = await res.json().catch(() => ({}));
    } catch { return paint(job, "error", "Network error. Check your connection and try again."); }
    // Busy or rate limited: wait our turn instead of failing the rest of the batch.
    if (res.status === 429 || res.status === 503) {
      const wait = res.status === 429 ? 15 : 3;
      paint(job, "pending", res.status === 429 ? `Rate limit reached, retrying in ${wait}s…` : "Scanner busy, retrying…");
      await sleep(wait * 1000);
      paint(job, "pending", "Scanning…");
      continue;
    }
    if (!res.ok) return paint(job, "error", typeof data.detail === "string" ? data.detail : "Scan failed");
    paint(job, "done", "", data);
    remember(data); loadHistory();
    return;
  }
  paint(job, "error", "Still rate limited. Try this one again in a minute.");
}

// --- History lives in this browser only: the server never lists other people's scans.
const HISTORY_KEY = "vigil.history";
function readHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; } catch { return []; }
}
function remember(r) {
  const entry = { id: r.id, target: r.final_url, grade: r.grade, score: r.score, created_at: r.started_at };
  const rows = [entry, ...readHistory().filter((s) => s.id !== r.id)].slice(0, 20);
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(rows)); } catch { /* storage unavailable */ }
}
function loadHistory() {
  $("#hist").replaceChildren(...readHistory().map((s) => el("tr", {},
    el("td", {}, el("strong", {}, s.grade), ` ${s.score}`),
    el("td", { class: "t" }, s.target),
    el("td", { class: "muted" }, new Date(s.created_at).toLocaleString()),
    el("td", { class: "links" },
      reportLink(s.id, ".pdf", { download: "" }, "PDF"), " · ",
      reportLink(s.id, ".docx", { download: "" }, "Word"), " · ",
      reportLink(s.id, "", { target: "_blank", rel: "noopener" }, "View")))));
  refreshLinks();
}

// --- Input: one URL, or a list pasted / imported from a file ----------------
const MAX_URLS = 10;
const parseUrls = (text) => [...new Set(text.split(/[\s,;]+/).filter(Boolean))];
$("#urls").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter" && !ev.shiftKey) { ev.preventDefault(); $("#f").requestSubmit(); }
});
$("#file").addEventListener("change", async (ev) => {
  const file = ev.target.files[0];
  if (!file) return;
  const urls = parseUrls(($("#urls").value + "\n" + await file.text()));
  $("#urls").value = urls.join("\n");
  ev.target.value = "";
});

// Scanning Vigil itself needs no permission from the visitor: it's our own site.
$("#try-self").addEventListener("click", () => {
  $("#urls").value = location.origin;
  $("#auth").checked = true;
  $("#f").requestSubmit();
});

$("#f").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = $("#err"); err.textContent = "";
  const urls = parseUrls($("#urls").value), { checks } = readOpts();
  if (!$("#auth").checked) { err.textContent = "Please confirm you're authorized to scan these sites."; return; }
  if (!urls.length) { err.textContent = "Enter at least one website."; return; }
  if (urls.length > MAX_URLS) { err.textContent = `You can scan up to ${MAX_URLS} sites at a time (you entered ${urls.length}).`; return; }
  if (!checks.length) { err.textContent = "Pick at least one check to run under “Customize”."; return; }

  const btn = $("#go"), box = $("#result");
  const jobs = urls.map((url) => ({ url, node: el("details", { class: "scan" }) }));
  box.replaceChildren(...jobs.map((j) => j.node));
  jobs.forEach((j) => paint(j, "queued", "Queued"));
  if (jobs.length === 1) jobs[0].node.open = true;
  btn.disabled = true; document.body.classList.add("scanning");
  try {
    for (const [i, job] of jobs.entries()) {
      btn.textContent = jobs.length > 1 ? `Scanning ${i + 1}/${jobs.length}…` : "Scanning…";
      await runJob(job, checks.length === $$("input[name=check]").length ? null : checks);
    }
  } finally { btn.disabled = false; btn.textContent = "Scan"; document.body.classList.remove("scanning"); }
});

restoreOpts();
loadHistory();
