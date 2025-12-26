import React from "react";
import { useNavigate } from "react-router-dom";
import { useWizard } from "../wizard/WizardContext.jsx";

export default function Step1() {
  const nav = useNavigate();
  const { answers, setAnswers } = useWizard();

  return (
    <div className="card">
      <div className="cardHeader">
        <div>
          <h2>Choose mode</h2>
          <div className="sub">Pick whether this device will act as a gateway or a client.</div>
        </div>
        <div className="badge">Step 1</div>
      </div>

      <div className="cardBody">
        <div className="grid">
          <div className="field">
            <div className="labelRow">
              <label>Mode</label>
              <span className="hint">Affects how the script configures networking</span>
            </div>
            <select
              value={answers.mode}
              onChange={(e) => setAnswers((a) => ({ ...a, mode: e.target.value }))}
            >
              <option value="gateway">gateway</option>
              <option value="client">client</option>
            </select>
          </div>

          <div className="actions">
            <button className="primary" onClick={() => nav("/step/2")}>Next</button>
          </div>
        </div>
      </div>
    </div>
  );
}
