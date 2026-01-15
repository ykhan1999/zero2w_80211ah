import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useWizard } from "../wizard/WizardContext.jsx";
import { useRef } from "react";

const BACKEND_URL = `${window.location.protocol}//${window.location.hostname}:5174`;

async function scanNetworks() {
  const res = await fetch(`${BACKEND_URL}/api/wifi/scan`);
  if (!res.ok) throw new Error("Scan failed");
  const data = await res.json();
  if (!data.ok) throw new Error(data.error || "Scan failed");
  return data.networks; // [{ssid,bssid,frequency,signal,secure,flags}]
}

function dbmToBars(dbm) {
  if (typeof dbm !== "number") return 0;
  if (dbm >= -50) return 4;
  if (dbm >= -60) return 3;
  if (dbm >= -70) return 2;
  if (dbm >= -80) return 1;
  return 0;
}

function SignalBars({ dbm }) {
  const bars = dbmToBars(dbm);
  return (
    <div className="sig" aria-label={`Signal ${bars}/4`}>
      <span className={`bar ${bars >= 1 ? "on" : ""}`} />
      <span className={`bar ${bars >= 2 ? "on" : ""}`} />
      <span className={`bar ${bars >= 3 ? "on" : ""}`} />
      <span className={`bar ${bars >= 4 ? "on" : ""}`} />
    </div>
  );
}

export default function Step2() {
  const didAutoScan = useRef(false);
  const nav = useNavigate();
  const { answers, setAnswers } = useWizard();

  const mode = answers.mode; // "gateway" | "client"

  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState("");
  const [networks, setNetworks] = useState([]);
  const [useHidden, setUseHidden] = useState(false);

  // ✅ NEW: controls whether the network list is expanded
  const [listOpen, setListOpen] = useState(false);

  useEffect(() => {
    setScanError("");
    setNetworks([]);
    setScanning(false);
    setUseHidden(false);
    setListOpen(false); // ✅ reset collapse state
  }, [mode]);


  useEffect(() => {
    if (mode !== "gateway") return;
    if (didAutoScan.current) return;

    didAutoScan.current = true;
    handleScan();
  }, [mode]);

  const canContinue = useMemo(() => {
    const ssidOk = (answers.regssid || "").trim().length > 0;

    if (mode === "gateway") {
      // upstream WiFi password optional (open networks allowed)
      return ssidOk;
    }

    // client mode: you're creating a hotspot -> require password
    const pwOk = (answers.regpw || "").trim().length >= 8; // change >=1 if you want "non-empty"
    return ssidOk && pwOk;
  }, [answers.regssid, answers.regpw, mode]);

  async function handleScan() {
    setScanning(true);
    setScanError("");
    try {
      const result = await scanNetworks();

      const cleaned = (result || [])
        .filter((n) => (n.ssid || "").trim().length > 0)
        .map((n) => ({
          ...n,
          ssid: (n.ssid || "").trim(),
          signal: typeof n.signal === "string" ? Number(n.signal) : n.signal,
        }));

      // Dedupe by SSID, keep strongest
      const bestBySsid = new Map();
      for (const n of cleaned) {
        const key = n.ssid;
        const existing = bestBySsid.get(key);

        const sNew = typeof n.signal === "number" ? n.signal : -999;
        const sOld = existing && typeof existing.signal === "number" ? existing.signal : -999;

        if (
          !existing ||
          sNew > sOld ||
          (sNew === sOld && !!n.secure && !existing.secure)
        ) {
          bestBySsid.set(key, n);
        }
      }

      const deduped = Array.from(bestBySsid.values());

      // Sort strongest first
      deduped.sort((a, b) => {
        const sa = typeof a.signal === "number" ? a.signal : -999;
        const sb = typeof b.signal === "number" ? b.signal : -999;
        return sb - sa;
      });

      setNetworks(deduped);
      setListOpen(true); // ✅ expand list after scan
    } catch (e) {
      setScanError(e?.message || "Unable to scan for networks.");
    } finally {
      setScanning(false);
    }
  }

  function chooseNetwork(ssid) {
    setUseHidden(false);
    setAnswers((a) => ({ ...a, regssid: ssid }));
    setListOpen(false); // ✅ collapse list after selection
  }

  function toggleHidden() {
    setUseHidden((v) => !v);
    setAnswers((a) => ({ ...a, regssid: "" }));
    setListOpen(false); // ✅ collapse when switching to hidden
  }

  return (
    <div className="card">
      <div className="cardHeader">
        <div>
          <h2>WiFi Network</h2>

          {mode === "gateway" ? (
            <div className="sub">
              Select a WiFi network to connect this device to. You can also add a hidden network.
            </div>
          ) : (
            <div className="sub">
              Client mode: Choose the SSID and password for the hotspot you want to create.
            </div>
          )}
        </div>
        <div className="badge">Step 2</div>
      </div>

      <div className="cardBody">
        <div className="grid">
          {mode === "gateway" && (
            <>
              <div className="field">
                <div className="labelRow">
                  <label>Available networks</label>
                  <span className="hint">Pick one or add hidden</span>
                </div>

                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <button type="button" onClick={handleScan} disabled={scanning}>
                    {scanning ? "Scanning…" : "Scan"}
                  </button>

                  <button
                    type="button"
                    onClick={toggleHidden}
                    className={useHidden ? "primary" : ""}
                    aria-pressed={useHidden}
                  >
                    {useHidden ? "Hidden network: ON" : "Add hidden network"}
                  </button>

                  {/* ✅ NEW: reopen list after it collapses */}
                  {!useHidden && networks.length > 0 && !listOpen && (
                    <button type="button" onClick={() => setListOpen(true)}>
                      Change network
                    </button>
                  )}

                  {/* Optional: allow manual collapse while open */}
                  {!useHidden && networks.length > 0 && listOpen && (
                    <button type="button" onClick={() => setListOpen(false)}>
                      Hide list
                    </button>
                  )}
                </div>

                {scanError && (
                  <div style={{ marginTop: 8 }} className="error">
                    {scanError}
                  </div>
                )}

                {/* ✅ Only show list when open */}
                {!useHidden && listOpen && networks.length > 0 && (
                  <div className="list">
                    {networks.map((n) => {
                      const selected = (answers.regssid || "") === n.ssid;
                      return (
                        <button
                          key={n.ssid}
                          type="button"
                          className={`listItem ${selected ? "selected" : ""}`}
                          onClick={() => chooseNetwork(n.ssid)}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", width: "100%" }}>
                            <span>{n.ssid}</span>
                            <span className="hint" style={{ display: "flex", alignItems: "center", gap: 10 }}>
                              <span>{n.secure ? "Secured" : "Open"}</span>
                              <SignalBars dbm={n.signal} />
                            </span>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                )}

                {!useHidden && networks.length === 0 && (
                  <div style={{ marginTop: 10 }} className="hint">
                    Tap <b>Scan</b> to find nearby WiFi networks.
                  </div>
                )}

                {!useHidden && networks.length > 0 && !listOpen && (
                  <div style={{ marginTop: 10 }} className="hint">
                    Selected: <b>{answers.regssid || "—"}</b> (tap <b>Change network</b> to pick another)
                  </div>
                )}
              </div>

              <div className="field">
                <div className="labelRow">
                  <label>WiFi Name (SSID)</label>
                  <span className="hint">Required</span>
                </div>

                {useHidden ? (
                  <input
                    value={answers.regssid || ""}
                    onChange={(e) => setAnswers((a) => ({ ...a, regssid: e.target.value }))}
                    placeholder="Enter hidden SSID"
                  />
                ) : (
                  <input
                    value={answers.regssid || ""}
                    readOnly
                    placeholder="Select a network above"
                  />
                )}
              </div>

              <div className="field">
                <div className="labelRow">
                  <label>WiFi Password</label>
                  <span className="hint">Optional</span>
                </div>
                <input
                  type="password"
                  value={answers.regpw || ""}
                  onChange={(e) => setAnswers((a) => ({ ...a, regpw: e.target.value }))}
                  placeholder="Enter WiFi password"
                />
              </div>
            </>
          )}

          {mode === "client" && (
            <>
              <div className="field">
                <div className="labelRow">
                  <label>Hotspot Name (SSID)</label>
                  <span className="hint">Required</span>
                </div>
                <input
                  value={answers.regssid || ""}
                  onChange={(e) => setAnswers((a) => ({ ...a, regssid: e.target.value }))}
                  placeholder="Choose a hotspot name"
                />
              </div>

              <div className="field">
                <div className="labelRow">
                  <label>Hotspot Password</label>
                  <span className="hint">Required</span>
                </div>
                <input
                  type="password"
                  value={answers.regpw || ""}
                  onChange={(e) => setAnswers((a) => ({ ...a, regpw: e.target.value }))}
                  placeholder="Choose a password"
                />
              </div>
            </>
          )}

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
