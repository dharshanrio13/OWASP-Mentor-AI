import { useRef, useState } from "react";
import { UploadCloud, Loader2, AlertCircle, FileArchive } from "lucide-react";
import { api } from "../api/client.js";

const MAX_MB = 20; // UX hint only; the backend enforces real limits.

export default function Upload({ onDone }) {
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const input = useRef(null);

  function pick(e) {
    const f = e.target.files?.[0];
    setError("");
    if (!f) return setFile(null);
    if (!f.name.toLowerCase().endsWith(".zip")) {
      setFile(null);
      return setError("Only .zip files are accepted.");
    }
    if (f.size > MAX_MB * 1024 * 1024) {
      setFile(null);
      return setError(`File is larger than ${MAX_MB} MB.`);
    }
    setFile(f);
  }

  async function submit() {
    if (!file || busy) return;
    setBusy(true);
    setError("");
    try {
      const scan = await api.upload(file);
      onDone(scan);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="page narrow">
      <h1>Scan a project</h1>
      <p className="muted">Upload a ZIP of your source code. The scanner checks it against the configured requirements.</p>
      <div className="card dropzone">
        <FileArchive size={36} />
        <p>{file ? file.name : "No file selected"}</p>
        {file && <p className="muted small">{(file.size / 1024).toFixed(1)} KB</p>}
        <input ref={input} type="file" accept=".zip,application/zip" onChange={pick} hidden />
        <button className="btn secondary" onClick={() => input.current?.click()} disabled={busy}>Choose ZIP file</button>
      </div>
      <div className="card">
        <h3>Upload restrictions</h3>
        <ul className="plain">
          <li>ZIP archives only, up to {MAX_MB} MB.</li>
          <li>This prototype accepts supported source-code and configuration files inside the archive. Other files may be ignored.</li>
          <li>These checks are for convenience. The backend performs the real validation.</li>
        </ul>
      </div>
      {error && <div className="alert" role="alert"><AlertCircle size={18} /> {error}</div>}
      <button className="btn primary" onClick={submit} disabled={!file || busy}>
        {busy ? <><Loader2 size={18} className="spin" /> Scanning…</> : <><UploadCloud size={18} /> Scan project</>}
      </button>
    </section>
  );
}
