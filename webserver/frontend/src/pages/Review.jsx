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

  function sendConfigFireAndForget(payloadObj) {
    const url = `${BACKEND_URL}/api/run`;
    const payload = JSON.stringify(payloadObj);

    // 1) Best effort: sendBeacon (designed for exactly this)
    try {
      if (navigator.sendBeacon) {
        const blob = new Blob([payload], { type: "application/json" });
        const ok = navigator.sendBeacon(url, blob);
        if (ok) return true; // queued for delivery
      }
    } catch {
      // fall through
    }

    // 2) Fallback: fetch with keepalive (lets the request continue after navigation)
    try {
      fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
        keepalive: true,
      }).catch(() => {
        // Swallow errors here — we intentionally don't block navigation.
      });
      return true;
    } catch {
      return false;
    }
  }

  async function run() {
    if (running) return;
    setRunning(true);
    setError(null);

    const ok = sendConfigFireAndForget({ answers });

    // Navigate immediately — we do NOT wait for script completion or response.
    nav("/applying", { replace: true });

    // If we couldn't even queue the request, set an error (rare; user may still see Applying page)
    if (!ok) {
      setError("Could not send settings to backend (browser blocked request). Try again.");
      setRunning(false);
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
            <button onClick={() => nav("/step/2")}>Back</button>
            <button className="primary" onClick={run} disabled={running}>
              {running ? "Applying..." : "Apply Settings"}
            </button>
          </div>

          {error && (
            <div className="field">
              <div className="labelRow">
                <label>Couldn’t start apply</label>
              </div>
              <pre>{error}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
