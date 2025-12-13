import React from "react";
import { useNavigate } from "react-router-dom";
import { useWizard } from "../wizard/WizardContext.jsx";

export default function Step2() {
  const nav = useNavigate();
  const { answers, setAnswers } = useWizard();

  const canContinue = answers.target.trim().length > 0;

  return (
    <div>
      <h2>Step 2: Target + options</h2>

      <div style={{ display: "grid", gap: 12 }}>
        <label>
          Target:&nbsp;
          <input
            value={answers.target}
            onChange={(e) => setAnswers((a) => ({ ...a, target: e.target.value }))}
            placeholder="e.g. rpi_zero2w_unnamed"
          />
        </label>

        <label>
          Verbosity:&nbsp;
          <select
            value={answers.verbosity}
            onChange={(e) => setAnswers((a) => ({ ...a, verbosity: e.target.value }))}
          >
            <option value="quiet">quiet</option>
            <option value="normal">normal</option>
            <option value="debug">debug</option>
          </select>
        </label>

        <label>
          <input
            type="checkbox"
            checked={answers.dryRun}
            onChange={(e) => setAnswers((a) => ({ ...a, dryRun: e.target.checked }))}
          />
          &nbsp;Dry run
        </label>
      </div>

      <div style={{ marginTop: 20, display: "flex", gap: 8 }}>
        <button onClick={() => nav("/step/1")}>Back</button>
        <button disabled={!canContinue} onClick={() => nav("/review")}>
          Review
        </button>
      </div>
    </div>
  );
}
