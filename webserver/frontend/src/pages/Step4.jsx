import React from "react";
import { useNavigate } from "react-router-dom";
import { useWizard } from "../wizard/WizardContext.jsx";

export default function Step1() {
  const nav = useNavigate();
  const { answers, setAnswers } = useWizard();

  return (
    <div>
      <h2>Step 4: Choose optimization</h2>

      <label>
        Mode:&nbsp;
        <select
          value={answers.optim}
          onChange={(e) => setAnswers((a) => ({ ...a, optim: e.target.value }))}
        >
          <option value="speed">speed</option>
          <option value="distance">distance</option>
        </select>
      </label>

      <div style={{ marginTop: 20, display: "flex", gap: 8 }}>
        <button onClick={() => nav("/step/3")}>Back</button>
        <button onClick={() => nav("/review")}>
          Review
        </button>
      </div>
    </div>
  );
}
