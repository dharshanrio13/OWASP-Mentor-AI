import { useState } from "react";
import { FileText, ArrowLeft } from "lucide-react";
import FindingCard from "./FindingCard.jsx";

const FILTERS = [["ALL", "All"], ["FINDING", "Findings"], ["NOT_VERIFIED", "Not verified"], ["PASSED", "Passed"]];

export default function Results({ scan, aiAvailable, onBack }) {
  const [filter, setFilter] = useState("ALL");
  if (!scan) return <section className="page"><p className="muted">No assessment selected.</p></section>;
  const date = scan.created_at && !Number.isNaN(Date.parse(scan.created_at)) ? new Date(scan.created_at).toLocaleString() : scan.created_at || "Not provided";
  const shown = scan.findings.filter((f) => filter === "ALL" || f.status === filter);
  return (
    <section className="page">
      <button className="link" onClick={onBack}><ArrowLeft size={16} /> Back to dashboard</button>
      <h1><FileText size={26} /> {scan.filename}</h1>
      <dl className="meta card">
        <div><dt>Scan ID</dt><dd>{scan.scan_id || "n/a"}</dd></div>
        <div><dt>Assessment date</dt><dd>{date}</dd></div>
        <div><dt>Overall status</dt><dd>{scan.overall_status}</dd></div>
        <div><dt>Passed</dt><dd>{scan.counts.passed}</dd></div>
        <div><dt>Findings</dt><dd>{scan.counts.failed}</dd></div>
        <div><dt>Not verified</dt><dd>{scan.counts.not_verified}</dd></div>
      </dl>
      <p className="muted small">A passed requirement means the scanner found no issue, not that the project is completely secure.</p>
      <div className="filters">
        {FILTERS.map(([k, l]) => (
          <button key={k} className={filter === k ? "active" : ""} onClick={() => setFilter(k)}>{l}</button>
        ))}
      </div>
      {shown.length === 0 ? <p className="muted">No rule results match this filter.</p> : shown.map((f) => (
        <FindingCard key={f.rule_id + f.file + f.line} finding={f} aiAvailable={aiAvailable} />
      ))}
    </section>
  );
}
