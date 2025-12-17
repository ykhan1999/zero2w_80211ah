import React from "react";
import { useNavigate } from "react-router-dom";
import { useWizard } from "../wizard/WizardContext.jsx";

export default function Step1() {
  const nav = useNavigate();
  const { answers, setAnswers } = useWizard();

  return (
    <div>
      <h2>Step 1: Choose mode</h2>

      <label>
        Mode:&nbsp;
        <select
          value={answers.mode}
          onChange={(e) => setAnswers((a) => ({ ...a, mode: e.target.value }))}
        >
          <option value="gateway">gateway</option>
          <option value="client">client</option>
        </select>
      </label>

      <div style={{ marginTop: 20 }}>
        <button onClick={() => nav("/step/2")}>Next</button>
      </div>
    </div>
  );
}
