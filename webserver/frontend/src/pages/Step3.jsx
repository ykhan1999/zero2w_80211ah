import React from "react";
import { useNavigate } from "react-router-dom";
import { useWizard } from "../wizard/WizardContext.jsx";

export default function Step3() {
  const nav = useNavigate();
  const { answers, setAnswers } = useWizard();

  const canContinueSSID = answers.halowssid.trim().length > 0;
  const canContinuePW = answers.halowpw.trim().length > 7;

  return (
    <div className="card">
      <div className="cardHeader">
        <div>
          <h2>HaLow credentials</h2>
          <div className="sub">Choose the HaLow network name and a password (min 8 chars).</div>
        </div>
        <div className="badge">Step 3</div>
      </div>

      <div className="cardBody">
        <div className="grid">
          <div className="field">
            <div className="labelRow">
              <label>HaLow Name (SSID)</label>
              <span className="hint">Required</span>
            </div>
            <input
              value={answers.halowssid}
              onChange={(e) => setAnswers((a) => ({ ...a, halowssid: e.target.value }))}
              placeholder="Choose HaLow network name"
            />
          </div>

          <div className="field">
            <div className="labelRow">
              <label>HaLow Password</label>
              <span className="hint">Min 8 characters</span>
            </div>
            <input
              value={answers.halowpw}
              onChange={(e) => setAnswers((a) => ({ ...a, halowpw: e.target.value }))}
              placeholder="Min 8 characters"
            />
          </div>

          <div className="actions">
            <button onClick={() => nav("/step/2")}>Back</button>
            <button
              className="primary"
              disabled={!canContinueSSID || !canContinuePW}
              onClick={() => nav("/step/4")}
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
