import { useState } from "react";
import { ChevronDown, ChevronUp, ScanSearch, Sparkles, BookOpen } from "lucide-react";

export const STATUS_LABEL = { PASSED: "Passed", FINDING: "Finding", NOT_VERIFIED: "Not verified" };

export function StatusBadge({ status }) {
  return <span className={`badge st-${status}`}>{STATUS_LABEL[status] || status}</span>;
}

export default function FindingCard({ finding: f, aiAvailable }) {
  const [open, setOpen] = useState(false);
  const adviceLabel = f.ai_generated ? "AI-generated advice" : aiAvailable ? "Explanation" : "Fallback explanation (not AI-generated)";
  return (
    <article className={`card finding bd-${f.status}`}>
      <button className="finding-head" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className="rid">{f.rule_id}</span>
        <span className="ftitle">{f.title}</span>
        {f.severity && <span className={`badge sev-${f.severity}`}>{f.severity}</span>}
        <StatusBadge status={f.status} />
        {open ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
      </button>
      {f.file && (
        <p className="muted small">{f.file}{f.line != null ? `, line ${f.line}` : ""}</p>
      )}
      {open && (
        <div className="detail">
          {f.status === "PASSED" && <p className="muted">No issue was detected for this requirement. This does not prove the project is completely secure.</p>}
          {f.status === "NOT_VERIFIED" && <p className="muted">The scanner could not verify this requirement from the uploaded files.</p>}
          <section>
            <h4><ScanSearch size={16} /> Scanner evidence</h4>
            <pre className="code">{f.evidence || "No evidence provided."}</pre>
          </section>
          {f.why_it_matters && <section><h4>Why it matters</h4><p>{f.why_it_matters}</p></section>}
          <section className="advice">
            <h4><Sparkles size={16} /> {adviceLabel}</h4>
            <p><strong>What it means: </strong>{f.explanation || "No explanation provided."}</p>
            <p><strong>Secure coding recommendation: </strong>{f.recommendation || "No recommendation provided."}</p>
            {f.example && (<><h4><BookOpen size={16} /> Safer code example</h4><pre className="code">{f.example}</pre></>)}
          </section>
        </div>
      )}
    </article>
  );
}
