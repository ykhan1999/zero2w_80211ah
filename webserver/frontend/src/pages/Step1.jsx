import React from "react";
import { useNavigate } from "react-router-dom";
import { useWizard } from "../wizard/WizardContext.jsx";

const BACKEND_URL = `${window.location.protocol}//${window.location.hostname}:5174`;

export default function Step1() {
  const nav = useNavigate();
  const { answers, setAnswers } = useWizard();

    useEffect(() => {
      // fire once when this page is visited
      fetch("${BACKEND_URL}/api/stoptimer", {
        method: "POST",
      }).catch(err => {
        console.error("Failed to stop timer:", err);
      });
    }, []);

  return (
    <div className="card">
      <div className="cardHeader">
        <div>
          <h2>Choose mode</h2>
          <div className="sub">Please select whether to set up as a gateway (connects to your wifi) or a client (creates a hotspot)</div>
        </div>
        <div className="badge">Step 1</div>
      </div>

      <div className="cardBody">
        <div className="grid">
          <div className="field">
            <div className="labelRow">
              <label>Mode</label>
              <span className="hint"> <br/>
              In gateway mode, your device will use the signal from your WiFi router to extend your network. <br/>
              In client mode, your device will receive the extended signal and set up a hotspot for you to use.</span>
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
