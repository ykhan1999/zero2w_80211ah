import React from "react";
import { useNavigate } from "react-router-dom";
import { useWizard } from "../wizard/WizardContext.jsx";

export default function Step4() {
  const nav = useNavigate();
  const { answers, setAnswers } = useWizard();

  return (
    <div className="card">
      <div className="cardHeader">
        <div>
          <h2>Optimization</h2>
          <div className="sub">Choose whether to prioritize speed or distance.</div>
        </div>
        <div className="badge">Step 4</div>
      </div>

      <div className="cardBody">
        <div className="grid">
          <div className="field">
            <div className="labelRow">
              <label>Optimization mode</label>
              <span className="hint">Used by the backend script</span>
            </div>
            <select
              value={answers.optim}
              onChange={(e) => setAnswers((a) => ({ ...a, optim: e.target.value }))}
            >
              <option value="speed">speed</option>
              <option value="distance">distance</option>
            </select>
          </div>

          <div className="actions">
            <button onClick={() => nav("/step/3")}>Back</button>
            <button className="primary" onClick={() => nav("/review")}>Review</button>
          </div>
        </div>
      </div>
    </div>
  );
}
