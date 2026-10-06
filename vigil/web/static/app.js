// Everything coming back from a scan (titles, evidence) can contain text from the
// scanned site, which is attacker-controlled. So we build the DOM with textContent
// only and never innerHTML with data, or the scanner itself would be an XSS vector.
const $ = (s) => document.querySelector(s);
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

function render(r) {
  const box = $("#result"); box.replaceChildren();
  const counts = Object.entries(r.summary).filter(([, n]) => n).map(([s, n]) => `${n} ${s}`).join(" · ");
  box.append(el("div", { class: "head" },
    el("div", { class: `grade g-${r.grade}` }, r.grade),
    el("div", {},
      el("div", { class: "url" }, r.final_url),
      el("div", { class: "muted" }, `Score ${r.score}/100 · ${r.duration_ms} ms · ${counts || "no issues"}`))));
  const base = `/scans/${encodeURIComponent(r.id)}/report`;
  box.append(el("div", { class: "report-panel" },
    el("div", { class: "report-copy" },
      el("strong", {}, "Get the full report"),
      el("span", { class: "muted" }, "A formatted, ready-to-share document with a summary, every finding and how to fix it.")),
    el("div", { class: "report-actions" },
      el("a", { class: "btn btn-primary", href: `${base}.pdf`, download: "" }, "⬇ Download PDF"),
      el("a", { class: "btn btn-secondary", href: `${base}.docx`, download: "" }, "⬇ Download Word"),
      el("a", { class: "btn btn-ghost", href: base, target: "_blank", rel: "noopener" }, "View online ↗"))));
  for (const f of r.findings) {
    box.append(el("div", { class: `card s-${f.severity}` },
      el("div", { class: `sev t-${f.severity}` }, `${f.severity} · ${f.check}`),
      el("h3", {}, f.title),
      el("div", {}, f.description),
      f.recommendation ? el("div", { class: "fix" }, el("strong", {}, "Fix: "), withCode(f.recommendation)) : null,
      f.evidence ? el("span", { class: "ev" }, f.evidence) : null));
  }
  if (r.passed.length) box.append(el("p", { class: "muted" }, "Passed: " + r.passed.join(", ")));
  for (const e of r.errors) box.append(el("p", { class: "muted" }, "Note: " + e));
}

// History lives in this browser only: the server never lists other people's scans.
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
  const report = (id) => `/scans/${encodeURIComponent(id)}/report`;
  $("#hist").replaceChildren(...readHistory().map((s) => el("tr", {},
    el("td", {}, el("strong", {}, s.grade), ` ${s.score}`),
    el("td", { class: "t" }, s.target),
    el("td", { class: "muted" }, new Date(s.created_at).toLocaleString()),
    el("td", { class: "links" },
      el("a", { href: `${report(s.id)}.pdf`, download: "" }, "PDF"), " · ",
      el("a", { href: `${report(s.id)}.docx`, download: "" }, "Word"), " · ",
      el("a", { href: report(s.id), target: "_blank", rel: "noopener" }, "View")))));
}

$("#f").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("#err").textContent = "";
  if (!$("#auth").checked) { $("#err").textContent = "Please confirm you're authorized to scan this site."; return; }
  const btn = $("#go"); btn.disabled = true; btn.textContent = "Scanning…";
  try {
    const res = await fetch("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: $("#url").value, authorized: true }) });
    const data = await res.json();
    if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Scan failed");
    render(data); remember(data); loadHistory();
  } catch (e) { $("#err").textContent = e.message; }
  finally { btn.disabled = false; btn.textContent = "Scan"; }
});
loadHistory();
