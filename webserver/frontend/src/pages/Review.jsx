import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useWizard } from "../wizard/WizardContext.jsx";

const BACKEND_URL = `${window.location.protocol}//${window.location.hostname}:5174`;

function PrettyRow({ label, value }) {
  return (
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        gap: 12,
        padding: "10px 12px",
        borderRadius: 12,
        border: "1px solid rgba(255,255,255,0.10)",
        background: "rgba(0,0,0,0.18)",
      }}
    >
      <div style={{ color: "rgba(255,255,255,0.72)", fontSize: 13 }}>{label}</div>
      <div style={{ fontWeight: 600 }}>{value}</div>
    </div>
  );
}

function Chip({ children }) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "6px 10px",
        borderRadius: 999,
        border: "1px solid rgba(255,255,255,0.14)",
        background: "rgba(255,255,255,0.04)",
        color: "rgba(255,255,255,0.85)",
        fontSize: 12,
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

export default function Review() {
  const nav = useNavigate();
  const { answers } = useWizard();
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);

  async function run() {
    setRunning(true);
    setError(null);

    try {
      // Same functionality: POST answers to backend
      await fetch(`${BACKEND_URL}/api/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ answers }),
      });

      // Instead of showing output, go to the friendly status page
      nav("/applying", { replace: true });
    } catch (e) {
      nav("/applying", { replace: true });
    } finally {
      setRunning(true);
    }
  }

  return (
    <div className="card">
      <div className="cardHeader">
        <div>
          <h2>Review your setup</h2>
          <div className="sub">Here’s what we’re about to apply to your device.</div>
        </div>
        <div className="badge">Final</div>
      </div>

      <div className="cardBody">
        <div className="grid">
          <div className="field">
            <div className="labelRow">
              <label>Settings summary</label>
            </div>

            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
              <Chip>Mode: {answers.mode}</Chip>
              <Chip>Optim: {answers.optim}</Chip>
              <Chip>WiFi SSID: {answers.regssid || "—"}</Chip>
              <Chip>HaLow SSID: {answers.halowssid || "—"}</Chip>
            </div>

            <div style={{ display: "grid", gap: 10 }}>
              <PrettyRow label="Mode" value={answers.mode} />
              <PrettyRow label="Optimization" value={answers.optim} />
              <PrettyRow label="WiFi SSID" value={answers.regssid || "—"} />
              <PrettyRow label="WiFi Password" value={answers.regpw ? "••••••••" : "—"} />
              <PrettyRow label="HaLow SSID" value={answers.halowssid || "—"} />
              <PrettyRow label="HaLow Password" value={answers.halowpw ? "••••••••" : "—"} />
            </div>
          </div>

          <div className="actions">
            <button onClick={() => nav("/step/4")}>Back</button>
            <button className="primary" onClick={run} disabled={running}>
              {running ? "Applying..." : "Apply Settings"}
            </button>
          </div>

          {error && (
            <div className="field">
              <div className="labelRow">
                <label>Error applying your settings - please try again</label>
              </div>
              <pre>{error}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
