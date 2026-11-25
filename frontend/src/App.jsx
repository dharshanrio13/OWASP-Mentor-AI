import { useEffect, useState } from "react";
import { Search, Gauge, GraduationCap, Code2 } from "lucide-react";
import Navbar from "./components/Navbar.jsx";
import Upload from "./components/Upload.jsx";
import Dashboard from "./components/Dashboard.jsx";
import Results from "./components/Results.jsx";
import { api } from "./api/client.js";

const FEATURES = [
  [Search, "Security analysis", "Scans your uploaded source and configuration files for common weaknesses."],
  [Gauge, "OWASP compliance tracking", "Tracks each configured requirement as passed, finding, or not verified."],
  [GraduationCap, "AI security tutor", "Explains each finding in beginner-friendly language."],
  [Code2, "Secure coding recommendations", "Suggests fixes and safer code where available."],
];

function Landing({ onStart }) {
  return (
    <section className="page hero">
      <h1>Build Secure. Learn Secure.</h1>
      <p className="lead">OWASP Mentor AI is a security compliance and learning assistant for student developers. Upload a project, see how it measures against a set of security requirements, and learn how to fix what the scanner finds.</p>
      <button className="btn primary big" onClick={onStart}>Start scanning</button>
      <div className="grid features">
        {FEATURES.map(([Icon, t, d]) => (
          <div className="card feature" key={t}><Icon size={24} /><h3>{t}</h3><p className="muted">{d}</p></div>
        ))}
      </div>
    </section>
  );
}

export default function App() {
  const [page, setPage] = useState("landing");
  const [scan, setScan] = useState(null);
  const [ai, setAi] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    api.aiStatus()
      .then((s) => setAi(Boolean(s?.available ?? s?.ai_available ?? s?.enabled)))
      .catch(() => setAi(false));
  }, []);

  const show = (s) => { setScan(s); setPage("results"); };
  const done = (s) => { setRefreshKey((k) => k + 1); show(s); };

  return (
    <>
      <Navbar page={page} onNavigate={setPage} ai={ai} />
      <main>
        {page === "landing" && <Landing onStart={() => setPage("upload")} />}
        {page === "upload" && <Upload onDone={done} />}
        {page === "dashboard" && <Dashboard ai={ai} onOpen={show} onNew={() => setPage("upload")} refreshKey={refreshKey} />}
        {page === "results" && <Results scan={scan} aiAvailable={ai} onBack={() => setPage("dashboard")} />}
      </main>
      <footer className="foot muted small">Scanner results are indicative and do not prove a project is completely secure.</footer>
    </>
  );
}
