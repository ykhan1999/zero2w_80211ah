import React from "react";
import { useNavigate } from "react-router-dom";
import { useWizard } from "../wizard/WizardContext.jsx";

export default function Step2() {
  const nav = useNavigate();
  const { answers, setAnswers } = useWizard();

  const canContinue = answers.regssid.trim().length > 0;

  return (
    <div>
      <h2>Step 2: Enter your WiFi network name and password</h2>

      <div style={{ display: "grid", gap: 12 }}>
        <label>
          WiFi Name (SSID):&nbsp;
          <input
            value={answers.regssid}
            onChange={(e) => setAnswers((a) => ({ ...a, regssid: e.regssid.value }))}
            placeholder="Your WiFi network name"
          />
        </label>

        <label>
          WiFi Password:&nbsp;
          <input
            value={answers.regpw}
            onChange={(e) => setAnswers((a) => ({ ...a, regpw: e.regpw.value }))}
            placeholder="Leave blank if none"
          />
        </label>

      </div>

      <div style={{ marginTop: 20, display: "flex", gap: 8 }}>
        <button onClick={() => nav("/step/1")}>Back</button>
        <button disabled={!canContinue} onClick={() => nav("/step/3")}>
          Review
        </button>
      </div>
    </div>
  );
}
