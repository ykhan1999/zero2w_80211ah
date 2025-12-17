import React from "react";
import { useNavigate } from "react-router-dom";
import { useWizard } from "../wizard/WizardContext.jsx";

export default function Step3() {
  const nav = useNavigate();
  const { answers, setAnswers } = useWizard();

  const canContinueSSID = answers.halowssid.trim().length > 0;
  const canContinuePW = answers.halowpw.trim().length > 7;

  return (
    <div>
      <h2>Step 2: Enter the HaLow network name and password</h2>

      <div style={{ display: "grid", gap: 12 }}>
        <label>
          HaLow Name (SSID):&nbsp;
          <input
            value={answers.halowssid}
            onChange={(e) => setAnswers((a) => ({ ...a, halowssid: e.halowssid.value }))}
            placeholder="Choose HaLow network name"
          />
        </label>

        <label>
          HaLow Password:&nbsp;
          <input
            value={answers.halowpw}
            onChange={(e) => setAnswers((a) => ({ ...a, halowpw: e.halowpw.value }))}
            placeholder="Cannot be blank"
          />
        </label>

      </div>

      <div style={{ marginTop: 20, display: "flex", gap: 8 }}>
        <button onClick={() => nav("/step/2")}>Back</button>
        <button disabled={!canContinueSSID & !canContinuePW} onClick={() => nav("/review")}>
          Review
        </button>
      </div>
    </div>
  );
}
