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
        body: JSON.stringify({ answers }),
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
    <div className="card">
      <div className="cardHeader">
        <div>
          <h2>Review</h2>
          <div className="sub">Double-check everything, then run the backend script.</div>
        </div>
        <div className="badge">Final</div>
      </div>

      <div className="cardBody">
        <div className="grid">
          <div className="field">
            <div className="labelRow">
              <label>Current answers</label>
              <span className="hint">Sent to /api/run</span>
            </div>
            <pre>{JSON.stringify(answers, null, 2)}</pre>
          </div>

          <div className="actions">
            <button onClick={() => nav("/step/2")}>Back</button>
            <button className="primary" onClick={run} disabled={running}>
              {running ? "Running..." : "Run Script"}
            </button>
          </div>

          {result && (
            <div className="field">
              <div className="labelRow">
                <label>Result</label>
                <span className="hint">{result.ok ? "Success" : "Error"}</span>
              </div>
              <pre>{JSON.stringify(result, null, 2)}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
