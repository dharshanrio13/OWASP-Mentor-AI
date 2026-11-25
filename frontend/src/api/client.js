const BASE = (import.meta.env.VITE_API_BASE_URL || "http://localhost:8000").replace(/\/$/, "");

// Demo session identifier only. It is NOT authentication.
export function getSessionId() {
  try {
    let id = sessionStorage.getItem("owasp_mentor_session");
    if (!id) {
      id = crypto.randomUUID();
      sessionStorage.setItem("owasp_mentor_session", id);
    }
    return id;
  } catch {
    return "demo-session-unavailable";
  }
}

async function request(path, options = {}) {
  let res;
  try {
    res = await fetch(BASE + path, {
      ...options,
      headers: { "X-Session-ID": getSessionId(), ...(options.headers || {}) },
    });
  } catch {
    throw new Error(`Cannot reach the backend at ${BASE}. Check that it is running.`);
  }
  let body = null;
  try { body = await res.json(); } catch { /* non-JSON body */ }
  if (!res.ok) {
    let msg = body && (body.detail ?? body.message ?? body.error);
    if (Array.isArray(msg)) msg = msg.map((m) => m?.msg || String(m)).join("; ");
    if (msg && typeof msg === "object") msg = JSON.stringify(msg);
    throw new Error(msg || `Request failed (HTTP ${res.status}).`);
  }
  return body;
}

const str = (v, d = "") => (typeof v === "string" ? v : v == null ? d : String(v));
const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
const listOf = (v, key) => (Array.isArray(v) ? v : Array.isArray(v?.[key]) ? v[key] : []);

export function normalizeStatus(s) {
  const v = str(s).toUpperCase().replace(/[\s-]/g, "_");
  if (v === "PASSED" || v === "PASS") return "PASSED";
  if (v === "FINDING" || v === "FAILED" || v === "FAIL") return "FINDING";
  return "NOT_VERIFIED";
}

export function normalizeScan(raw) {
  const r = raw && typeof raw === "object" ? raw : {};
  const c = r.counts && typeof r.counts === "object" ? r.counts : {};
  const findings = listOf(r.findings, "findings").map((f, i) => ({
    rule_id: str(f?.rule_id, `RULE-${i + 1}`),
    title: str(f?.title, "Untitled requirement"),
    status: normalizeStatus(f?.status),
    severity: str(f?.severity).toUpperCase(),
    file: str(f?.file),
    line: f?.line == null || f?.line === "" ? null : num(f.line),
    evidence: str(f?.evidence),
    explanation: str(f?.explanation),
    recommendation: str(f?.recommendation),
    why_it_matters: str(f?.why_it_matters ?? f?.impact),
    example: str(f?.safer_example ?? f?.example_fix ?? f?.example),
    ai_generated: f?.ai_generated === true,
  }));
  return {
    scan_id: str(r.scan_id ?? r.id),
    filename: str(r.filename, "Unknown file"),
    created_at: str(r.created_at ?? r.assessed_at ?? r.date),
    overall_status: str(r.overall_status, "UNKNOWN"),
    counts: {
      passed: num(c.passed),
      failed: num(c.failed ?? c.findings),
      not_verified: num(c.not_verified),
    },
    findings,
  };
}

export const api = {
  health: () => request("/api/health"),
  rules: async () => listOf(await request("/api/rules"), "rules").map((x, i) => ({
    rule_id: str(x?.rule_id ?? x?.id, `RULE-${i + 1}`),
    title: str(x?.title, "Untitled requirement"),
  })),
  aiStatus: () => request("/api/ai/status"),
  scans: async () => listOf(await request("/api/scans"), "scans").map(normalizeScan),
  scan: async (id) => normalizeScan(await request(`/api/scans/${encodeURIComponent(id)}`)),
  upload: async (file) => {
    const fd = new FormData();
    fd.append("file", file); // field name must be "file"; browser sets the multipart boundary
    return normalizeScan(await request("/api/scans/upload", { method: "POST", body: fd }));
  },
};
