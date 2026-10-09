// Vigil's browser extension: grade the current tab with a passive scan.
// Scan results contain text from the scanned (possibly hostile) site, so the DOM is built
// with textContent only, never innerHTML, exactly like the dashboard.
const API = "https://vigil-psi-liard.vercel.app";  // Vigil deployment the extension talks to
const out = document.getElementById("out");

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) k === "class" ? (n.className = v) : n.setAttribute(k, v);
  for (const k of kids) if (k != null) n.append(k);
  return n;
}
function withCode(text) {
  const frag = document.createDocumentFragment();
  text.split(/`([^`]+)`/).forEach((p, i) => frag.append(i % 2 ? el("code", {}, p) : p));
  return frag;
}
const link = (href, label, cls = "") => el("a", { href, target: "_blank", rel: "noopener", class: cls }, label);
const show = (...nodes) => out.replaceChildren(...nodes.filter(Boolean));  // skip empty sections

function render(r, pageUrl) {
  const counts = Object.entries(r.summary).filter(([, n]) => n).map(([s, n]) => `${n} ${s}`).join(" · ");
  const report = `${API}/scans/${encodeURIComponent(r.id)}/report`;
  show(
    el("section", { class: "head" },
      el("div", { class: `grade g-${r.grade}` }, r.grade),
      el("div", { class: "who" },
        el("div", { class: "url" }, new URL(r.final_url).host),
        el("div", { class: "muted" }, `Score ${r.score}/100 · ${counts || "no issues"}`))),
    el("div", { class: "actions" },
      link(report, "Full report ↗", "btn primary"),
      link(`${report}.pdf`, "PDF", "btn")),
    r.findings.length ? el("ul", { class: "findings" }, ...r.findings.map((f) =>
      el("li", { class: `s-${f.severity}` },
        el("details", {},
          el("summary", {}, el("span", { class: `sev t-${f.severity}` }, f.severity), f.title),
          el("p", {}, f.description),
          f.recommendation ? el("p", { class: "fix" }, el("strong", {}, "Fix: "), withCode(f.recommendation)) : null,
          f.evidence ? el("code", { class: "ev" }, f.evidence) : null)))) : el("p", {}, "No issues found."),
    r.passed.length ? el("p", { class: "muted" }, "Passed: " + r.passed.join(", ")) : null,
    el("p", { class: "note" }, "Passive scan: it only reads what any visitor sees, so exposed-file checks were skipped. ",
      link(`${API}/?url=${encodeURIComponent(pageUrl)}`, "Run a full audit ↗")),
  );
}

async function main() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const pageUrl = tab?.url || "";
  if (!/^https?:\/\//.test(pageUrl)) {
    return show(el("p", { class: "msg" }, "Vigil grades websites. Open an http:// or https:// page and click again."));
  }
  show(el("div", { class: "loading" }, el("div", { class: "spinner" }),
    el("p", {}, "Grading ", el("strong", {}, new URL(pageUrl).host), "…"),
    el("p", { class: "muted" }, "Usually takes a few seconds.")));
  try {
    const res = await fetch(`${API}/api/scans`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: pageUrl, passive: true }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : `Scan failed (HTTP ${res.status})`);
    render(data, pageUrl);
  } catch (e) {
    show(el("p", { class: "msg err" }, e.message === "Failed to fetch"
      ? "Couldn't reach Vigil. Check your connection and try again." : e.message));
  }
}

main();
