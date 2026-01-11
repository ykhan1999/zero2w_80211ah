import React from "react";
import { useNavigate } from "react-router-dom";

export default function Applying() {
  const nav = useNavigate();

  return (
    <div className="card">
      <div className="cardHeader">
        <div>
          <h2>Applying your settings</h2>
          <div className="sub">
            Your settings have been sent to the device — please check your device's screen for the current status.
          </div>
        </div>
        <div className="badge">Status</div>
      </div>

      <div className="cardBody">
        <div className="grid">
          <div
            style={{
              padding: 14,
              borderRadius: 14,
              border: "1px solid rgba(255,255,255,0.12)",
              background: "rgba(0,0,0,0.22)",
              color: "rgba(255,255,255,0.78)",
              lineHeight: 1.5,
              fontSize: 13,
            }}
          >
            Note - once the process is completed, your device may reboot with the new settings.
          </div>

          <div className="actions">
            <button onClick={() => nav("/step/1")}>Start Over</button>
            <button className="primary" onClick={() => nav("/review")}>
              View Review
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
