import { ShieldCheck, LayoutDashboard, UploadCloud } from "lucide-react";

export default function Navbar({ page, onNavigate, ai }) {
  const links = [
    ["dashboard", "Dashboard", LayoutDashboard],
    ["upload", "New scan", UploadCloud],
  ];
  const label = ai === null ? "Checking AI…" : ai ? "Local AI available" : "Fallback explanations (no AI)";
  return (
    <header className="nav">
      <button className="brand" onClick={() => onNavigate("landing")} aria-label="OWASP Mentor AI home">
        <ShieldCheck size={22} /> <span>OWASP Mentor AI</span>
      </button>
      <nav className="nav-links">
        {links.map(([key, text, Icon]) => (
          <button key={key} className={page === key ? "active" : ""} onClick={() => onNavigate(key)}>
            <Icon size={16} /> {text}
          </button>
        ))}
      </nav>
      <span className={`pill ${ai ? "pill-ok" : "pill-muted"}`}>{label}</span>
    </header>
  );
}
