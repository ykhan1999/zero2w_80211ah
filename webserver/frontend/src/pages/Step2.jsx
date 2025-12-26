import React from "react";
import { useNavigate } from "react-router-dom";
import { useWizard } from "../wizard/WizardContext.jsx";

export default function Step2() {
  const nav = useNavigate();
  const { answers, setAnswers } = useWizard();

  const canContinue = answers.regssid.trim().length > 0;

  return (
    <div className="card">
      <div className="cardHeader">
        <div>
          <h2>Regular WiFi credentials</h2>
          <div className="sub">Gateway mode: Enter the SSID and password for your regular WiFi network. \n 
            Client mode: Enter the SSID and password of the hotspot that you want to create..</div>
        </div>
        <div className="badge">Step 2</div>
      </div>

      <div className="cardBody">
        <div className="grid">
          <div className="field">
            <div className="labelRow">
              <label>WiFi Name (SSID)</label>
              <span className="hint">Required</span>
            </div>
            <input
              value={answers.regssid}
              onChange={(e) => setAnswers((a) => ({ ...a, regssid: e.target.value }))}
              placeholder="Your WiFi network name"
            />
          </div>

          <div className="field">
            <div className="labelRow">
              <label>WiFi Password</label>
              <span className="hint">Required</span>
            </div>
            <input
              value={answers.regpw}
              onChange={(e) => setAnswers((a) => ({ ...a, regpw: e.target.value }))}
              placeholder="Cannot be blank"
            />
          </div>

          <div className="actions">
            <button onClick={() => nav("/step/1")}>Back</button>
            <button className="primary" disabled={!canContinue} onClick={() => nav("/step/3")}>
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
