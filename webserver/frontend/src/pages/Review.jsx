import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useWizard } from "../wizard/WizardContext.jsx";

const BACKEND_URL = `${window.location.protocol}//${window.location.hostname}:5174`;


export default function Review() {
  const nav = useNavigate();
  const { answers } = useWizard();
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);

  async function run() {
    setRunning(true);
    setResult(null);
    try {
      const resp = await fetch(`${BACKEND_URL}/api/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ answers })
      });
      const data = await resp.json();
      setResult(data);
    } catch (e) {
      setResult({ ok: false, error: e.message });
    } finally {
      setRunning(false);
    }
  }

  return (
    <div>
      <h2>Review</h2>
      <pre style={{ background: "#f6f6f6", padding: 12, borderRadius: 8 }}>
        {JSON.stringify(answers, null, 2)}
      </pre>

      <div style={{ display: "flex", gap: 8 }}>
        <button onClick={() => nav("/step/2")}>Back</button>
        <button onClick={run} disabled={running}>
          {running ? "Running..." : "Run Script"}
        </button>
      </div>

      {result && (
        <div style={{ marginTop: 16 }}>
          <h3>Result</h3>
          <pre style={{ background: "#f6f6f6", padding: 12, borderRadius: 8 }}>
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
